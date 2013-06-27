/******************************************************************************
 * arch/x86/mm/mem_event.c
 *
 * Memory event support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <asm/domain.h>
#include <xen/event.h>
#include <xen/wait.h>
#include <asm/p2m.h>
#include <asm/mem_event.h>
#include <asm/mem_paging.h>
#include <asm/mem_access.h>

/* for public/io/ring.h macros */
#define xen_mb()   mb()
#define xen_rmb()  rmb()
#define xen_wmb()  wmb()

#define mem_event_ring_lock_init(_med)  spin_lock_init(&(_med)->ring_lock)
#define mem_event_ring_lock(_med)       spin_lock(&(_med)->ring_lock)
#define mem_event_ring_unlock(_med)     spin_unlock(&(_med)->ring_lock)

static int mem_event_enable(struct domain *d,
                            xen_domctl_mem_event_op_t *mec,
                            int pause_flag,
                            struct mem_event_domain *med)
{
    int rc;
    struct domain *dom_mem_event = current->domain;
    struct vcpu *v = current;
    unsigned long ring_addr = mec->ring_addr;
    unsigned long shared_addr = mec->u.shared_addr;
    l1_pgentry_t l1e;
    unsigned long gfn;
    p2m_type_t p2mt;
    mfn_t ring_mfn;
    mfn_t shared_mfn;

    /* Only one helper at a time. If the helper crashed,
     * the ring is in an undefined state and so is the guest.
     */
    if ( med->ring_page )
        return -EBUSY;

    /* Get MFN of ring page */
    guest_get_eff_l1e(v, ring_addr, &l1e);
    gfn = l1e_get_pfn(l1e);
    ring_mfn = gfn_to_mfn(p2m_get_hostp2m(dom_mem_event), gfn, &p2mt);

    if ( unlikely(!mfn_valid(mfn_x(ring_mfn))) )
        return -EINVAL;

    /* Get MFN of shared page */
    guest_get_eff_l1e(v, shared_addr, &l1e);
    gfn = l1e_get_pfn(l1e);
    shared_mfn = gfn_to_mfn(p2m_get_hostp2m(dom_mem_event), gfn, &p2mt);

    if ( unlikely(!mfn_valid(mfn_x(shared_mfn))) )
        return -EINVAL;

    /* Map ring and shared pages */
    med->ring_page = map_domain_page(mfn_x(ring_mfn));
    med->shared_page = map_domain_page(mfn_x(shared_mfn));

    /* Allocate event channel */
    rc = alloc_unbound_xen_event_channel(d->vcpu[0],
                                         current->domain->domain_id);
    if ( rc < 0 )
        goto err;

    ((mem_event_shared_page_t *)med->shared_page)->port = rc;
    med->xen_port = rc;

    /* Prepare ring buffer */
    FRONT_RING_INIT(&med->front_ring,
                    (mem_event_sring_t *)med->ring_page,
                    PAGE_SIZE);

    mem_event_ring_lock_init(med);

    med->pause_flag = pause_flag;

    init_waitqueue_head(&med->wq);

    /* Wake any VCPUs paused for memory events */
    mem_event_wake_waiters(d, med);

    return 0;

 err:
    unmap_domain_page(med->shared_page);
    med->shared_page = NULL;

    unmap_domain_page(med->ring_page);
    med->ring_page = NULL;

    return rc;
}

static int mem_event_disable(struct mem_event_domain *med)
{
    if (!list_empty(&med->wq.list))
        return -EBUSY;

    unmap_domain_page(med->ring_page);
    med->ring_page = NULL;

    unmap_domain_page(med->shared_page);
    med->shared_page = NULL;

    return 0;
}

static int _mem_event_put_request(struct domain *d,
                                  struct mem_event_domain *med,
                                  mem_event_request_t *req)
{
    mem_event_front_ring_t *front_ring;
    int free_req, claimed_req;
    RING_IDX req_prod;

    mem_event_ring_lock(med);

    free_req = RING_FREE_REQUESTS(&med->front_ring);
    /* Foreign requests must succeed because their vcpus can not sleep */
    claimed_req = med->foreign_producers;
    if ( !free_req || ( current->domain == d && free_req <= claimed_req ) ) {
        mem_event_ring_unlock(med);
        return 0;
    }

    front_ring = &med->front_ring;
    req_prod = front_ring->req_prod_pvt;

    /* Copy request */
    memcpy(RING_GET_REQUEST(front_ring, req_prod), req, sizeof(*req));
    req_prod++;

    /* Update accounting */
    if ( current->domain == d )
        med->target_producers--;
    else
        med->foreign_producers--;

    /* Update ring */
    front_ring->req_prod_pvt = req_prod;
    RING_PUSH_REQUESTS(front_ring);

    mem_event_ring_unlock(med);

    notify_via_xen_event_channel(d, med->xen_port);

    return 1;
}

void mem_event_put_request(struct domain *d, struct mem_event_domain *med,
                           mem_event_request_t *req)
{
    /* Go to sleep if request came from guest */
    if (current->domain == d) {
        wait_event(med->wq, _mem_event_put_request(d, med, req));
        return;
    }
    /* Ring was full anyway, unable to sleep in non-guest context */
    if (!_mem_event_put_request(d, med, req))
        printk("Failed to put memreq: d %u t %x f %x gfn %lx\n", d->domain_id,
                req->type, req->flags, (unsigned long)req->gfn);
}

void mem_event_get_response(struct mem_event_domain *med, mem_event_response_t *rsp)
{
    mem_event_front_ring_t *front_ring;
    RING_IDX rsp_cons;

    mem_event_ring_lock(med);

    front_ring = &med->front_ring;
    rsp_cons = front_ring->rsp_cons;

    /* Copy response */
    memcpy(rsp, RING_GET_RESPONSE(front_ring, rsp_cons), sizeof(*rsp));
    rsp_cons++;

    /* Update ring */
    front_ring->rsp_cons = rsp_cons;
    front_ring->sring->rsp_event = rsp_cons + 1;

    mem_event_ring_unlock(med);
}

/**
 * mem_event_wake_requesters - Wake vcpus waiting for room in the ring
 * @d: guest domain
 * @med: mem_event ring
 *
 * mem_event_wake_requesters() will wakeup vcpus waiting for room in the
 * ring. Only as many as can place another request in the ring will
 * resume execution.
 */
void mem_event_wake_requesters(struct mem_event_domain *med)
{
    int free_req;

    mem_event_ring_lock(med);
    free_req = RING_FREE_REQUESTS(&med->front_ring);
    free_req -= med->foreign_producers;
    mem_event_ring_unlock(med);

    if ( free_req )
        wake_up_nr(&med->wq, free_req);
}

/**
 * mem_event_wake_waiters - Wake all vcpus waiting for the ring
 * @d: guest domain
 * @med: mem_event ring
 *
 * mem_event_wake_waiters() will wakeup all vcpus waiting for the ring to
 * become available.
 */
void mem_event_wake_waiters(struct domain *d, struct mem_event_domain *med)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        if ( test_and_clear_bit(med->pause_flag, &v->pause_flags) )
            vcpu_wake(v);
}

/**
 * mem_event_mark_and_sleep - Put vcpu to sleep
 * @v: guest vcpu
 * @med: mem_event ring
 *
 * mem_event_mark_and_sleep() tags vcpu and put it to sleep.
 * The vcpu will resume execution in mem_event_wake_waiters().
 */
void mem_event_mark_and_sleep(struct vcpu *v, struct mem_event_domain *med)
{
    set_bit(med->pause_flag, &v->pause_flags);
    vcpu_sleep_nosync(v);
}

/**
 * mem_event_release_slot - Release a claimed slot
 * @med: mem_event ring
 *
 * mem_event_release_slot() releases a claimed slot in the mem_event ring.
 */
void mem_event_release_slot(struct domain *d, struct mem_event_domain *med)
{
    mem_event_ring_lock(med);
    if ( current->domain == d )
        med->target_producers--;
    else
        med->foreign_producers--;
    mem_event_ring_unlock(med);
}

/**
 * mem_event_claim_slot - Check state of a mem_event ring
 * @d: guest domain
 * @med: mem_event ring
 *
 * Return codes: < 0: the ring is not yet configured
 *                 0: the ring has some room
 *               > 0: the ring is full
 *
 * mem_event_claim_slot() checks the state of the given mem_event ring.
 * If the current vcpu belongs to the guest domain, the function assumes that
 * mem_event_put_request() will sleep until the ring has room again.
 * A guest can always place at least one request.
 *
 * If the current vcpu does not belong to the target domain the caller must try
 * again until there is room. A slot is claimed and the caller can place a
 * request. If the caller does not need to send a request, the claimed slot has
 * to be released with mem_event_release_slot().
 */
int mem_event_claim_slot(struct domain *d, struct mem_event_domain *med)
{
    int free_req;
    int ring_full = 1;

    if ( !med->ring_page )
        return -1;

    mem_event_ring_lock(med);

    free_req = RING_FREE_REQUESTS(&med->front_ring);

    if ( current->domain == d ) {
        med->target_producers++;
        ring_full = 0;
    } else if ( med->foreign_producers + med->target_producers + 1 < free_req )
    {
        med->foreign_producers++;
        ring_full = 0;
    }

    mem_event_ring_unlock(med);

    return ring_full;
}

int mem_event_domctl(struct domain *d, xen_domctl_mem_event_op_t *mec,
                     XEN_GUEST_HANDLE(void) u_domctl)
{
    int rc;

    if ( unlikely(d == current->domain) )
    {
        gdprintk(XENLOG_INFO, "Tried to do a memory paging op on itself.\n");
        return -EINVAL;
    }

    if ( unlikely(d->is_dying) )
    {
        gdprintk(XENLOG_INFO, "Ignoring memory paging op on dying domain %u\n",
                 d->domain_id);
        return 0;
    }

    if ( unlikely(d->vcpu == NULL) || unlikely(d->vcpu[0] == NULL) )
    {
        gdprintk(XENLOG_INFO,
                 "Memory paging op on a domain (%u) with no vcpus\n",
                 d->domain_id);
        return -EINVAL;
    }

    /* TODO: XSM hook */
#if 0
    rc = xsm_mem_event_control(d, mec->op);
    if ( rc )
        return rc;
#endif

    rc = -ENOSYS;

    switch ( mec->mode )
    {
    case XEN_DOMCTL_MEM_EVENT_OP_PAGING:
    {
        struct mem_event_domain *med = &d->mem_event->paging;
        rc = -EINVAL;

        switch( mec->op )
        {
        case XEN_DOMCTL_MEM_EVENT_OP_PAGING_ENABLE:
        {
            struct p2m_domain *p2m = p2m_get_hostp2m(d);
            rc = -ENODEV;
            /* Only HAP is supported */
            if ( !hap_enabled(d) )
                break;

            /* Currently only EPT is supported */
            if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL )
                break;

            rc = -EXDEV;
            /* Disallow paging in a PoD guest */
            if ( p2m->pod.entry_count )
                break;

            rc = -ENOEXEC;
            /* Disallow paging in a PoD guest */
            if ( mec->gfn != MEM_EVENT_PAGING_AGE )
	    {
                gdprintk(XENLOG_INFO, "Expected paging age %lx, got %lx\n",
                         MEM_EVENT_PAGING_AGE, mec->gfn);
                break;
	    }

            rc = mem_event_enable(d, mec, _VPF_mem_paging, med);
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_PAGING_DISABLE:
        {
            if ( med->ring_page )
                rc = mem_event_disable(med);
        }
        break;

        default:
        {
            if ( med->ring_page )
                rc = mem_paging_domctl(d, mec, u_domctl);
        }
        break;
        }
    }
    break;

    case XEN_DOMCTL_MEM_EVENT_OP_ACCESS: 
    {
        struct mem_event_domain *med = &d->mem_event->access;
        rc = -EINVAL;

        switch( mec->op )
        {
        case XEN_DOMCTL_MEM_EVENT_OP_ACCESS_ENABLE:
        {
            rc = -ENODEV;
            /* Only HAP is supported */
            if ( !hap_enabled(d) )
                break;

            /* Currently only EPT is supported */
            if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL )
                break;

            rc = mem_event_enable(d, mec, _VPF_mem_access, med);
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_ACCESS_DISABLE:
        {
            if ( med->ring_page )
                rc = mem_event_disable(med);
        }
        break;

        default:
        {
            if ( med->ring_page )
                rc = mem_access_domctl(d, mec, u_domctl);
        }
        break;
        }
    }
    break;
    }

    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
