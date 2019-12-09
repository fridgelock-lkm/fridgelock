#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stropts.h>
#include <mntent.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_PREFIX "fridgelock_stage2: "
#define LOG(args...) printf(LOG_PREFIX args)

int redirect_stdout_to_kernel() {
	int kernel_log = open("/dev/kmsg", O_WRONLY);
	if (kernel_log < 0) {
		puts("Could not open kernel buffer");
		return -1;
	}
	
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	dup2(kernel_log, STDOUT_FILENO);
	dup2(kernel_log, STDERR_FILENO);

	return 0;
}

int run(char* prg, char** args) {
	char buf[255] = { 0 };
	for(int i=0;args[i] != NULL; i++) {
		strcat(buf, args[i]);
		strcat(buf, " ");
	}

	LOG("Executing %s with args %s\n", prg, buf);
	int ret = fork();
	if(ret == 0) {
		execv(prg, args);
		return -1;
	} else {
		int wstatus = 0;
		// Wait for completion
		waitpid(ret, &wstatus, 0);
		LOG("Child exited with status %d\n", wstatus);
		return wstatus;
	}
}

int main(int argc, char *argv[])
{
	if(redirect_stdout_to_kernel()) {
		return -1;
	}	
	
	/* open the device so the module can save *current */
	int dev = open("/dev/ramenc", O_RDWR);
	if (dev < 0) {
		LOG("Failed opening device\n");
		return -1;
	}
	
	unsigned short length = 0;
	for(int i=1;i<argc;i++) {
		length += strlen(argv[i]) + 1;
	}
	char *buf = malloc(length + sizeof(unsigned short));
	*(unsigned short*) buf = length;

	int offset = sizeof(length);
	for(int i=1;i<argc;i++) {
		strcpy(buf+offset, argv[i]);
		offset += strlen(argv[i]) + 1;
	}
	
	ioctl(dev, 1337, buf);

	ioctl(dev, 0);

	int console = open("/dev/console", O_RDWR);
	if (console < 0) {
		LOG("Error opening console\n");
		return -1;
	}

	dup2(console, fileno(stdin));
	dup2(console, fileno(stdout));
	dup2(console, fileno(stderr));

	// Resume devices on command line
	for(int i=1;i<argc;i++) {
		char *args[] = {"/bin/cryptsetup", "luksResume", argv[i], NULL};
		//char *args[] = {"/bin/strace", "/bin/cryptsetup", "luksResume", argv[i], NULL};
		puts("About to run cryptsetup to resume partition!");
		if (run(args[0], args)) {
			puts("Resuming via cryptsetup failed!");
			i--;
			continue;
		}
		puts("Successfully resumed via cryptsetup!");
	}

	ioctl(dev, 1);
}
