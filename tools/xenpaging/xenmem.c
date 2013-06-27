#include <stdio.h>
#include <xc_private.h>

static void dump_mem(const char *domid)
{
	xc_interface *xch;
	xc_dominfo_t info;
	unsigned char handle[16];
	char uuid[16 * 2 + 1];
	int i;

	xch = xc_interface_open(NULL, NULL, 0);
	if (!xch)
		perror("xc_interface_open");
	else {
		i = xc_domain_getinfo(xch, atoi(domid), 1, &info);
		if (i != 1)
			perror("xc_domain_getinfo");
		else {
			printf("domid\t%u\n", info.domid);
			printf("ssidref\t%u\n", info.ssidref);
			printf("dying\t%u\n", info.dying);
			printf("crashed\t%u\n", info.crashed);
			printf("shutdown\t%u\n", info.shutdown);
			printf("paused\t%u\n", info.paused);
			printf("blocked\t%u\n", info.blocked);
			printf("running\t%u\n", info.running);
			printf("hvm\t%u\n", info.hvm);
			printf("debugged\t%u\n", info.debugged);
			printf("shutdown_reason\t%u\n", info.shutdown_reason);
			printf("nr_pages\t%lu\t%lu KiB\t%lu MiB\n", info.nr_pages, info.nr_pages * 4, info.nr_pages * 4 / 1024);
			printf("nr_shared_pages\t%lu\t%lu KiB\t%lu MiB\n", info.nr_shared_pages, info.nr_shared_pages * 4, info.nr_shared_pages * 4 / 1024);
			printf("nr_paged_pages\t%lu\t%lu KiB\t%lu MiB\n", info.nr_paged_pages, info.nr_paged_pages * 4, info.nr_paged_pages * 4 / 1024);
			printf("max_memkb\t%lu KiB\t%lu MiB\n", info.max_memkb, info.max_memkb / 1024);
			printf("shared_info_frame\t%lu\t%lx\n", info.shared_info_frame, info.shared_info_frame);
			printf("cpu_time\t%llu\t%016llx\n", (unsigned long long)info.cpu_time, (unsigned long long)info.cpu_time);
			printf("nr_online_vcpus\t%u\n", info.nr_online_vcpus);
			printf("max_vcpu_id\t%u\n", info.max_vcpu_id);
			printf("cpupool\t%u\n", info.cpupool);

			memcpy(&handle, &info.handle, sizeof(handle));
			uuid[0] = '\0';
			for (i = 0; i < sizeof(handle); i++)
				snprintf(&uuid[i * 2], sizeof(uuid) - strlen(uuid), "%02x", handle[i]);
			printf("handle\t%s\n", uuid);
		}
		if (xc_interface_close(xch) < 0)
			perror("xc_interface_close");
	}
}

int main(int argc, char **argv)
{
	if (argv[1])
		dump_mem(argv[1]);
	return 0;
}
