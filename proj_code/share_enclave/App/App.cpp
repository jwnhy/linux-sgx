#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <pwd.h>
#include <unistd.h>
#define MAX_PATH FILENAME_MAX

#include "App.h"
#include "Enclave_u.h"
#include "TranslateVirtual.h"
#include "sgx_enclave_common.h"
#include "sgx_enclave_info.h"
#include "sgx_urts.h"
#include <stdio.h>
#include <sys/sem.h>
#include <sys/shm.h>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
  sgx_status_t err;
  const char *msg;
  const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL},
    {SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL},
    {SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL},
    {SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL},
    {SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL},
    {SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL},
    {SGX_ERROR_NO_DEVICE, "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX "
     "driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL},
    {SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL},
    {SGX_ERROR_DEVICE_BUSY, "SGX device was busy.", NULL},
    {SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized.", NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL},
    {SGX_ERROR_MEMORY_MAP_FAILURE, "Failed to reserve memory for the enclave.",
     NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
  size_t idx = 0;
  size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

  for (idx = 0; idx < ttl; idx++) {
    if (ret == sgx_errlist[idx].err) {
      if (NULL != sgx_errlist[idx].sug)
        printf("Info: %s\n", sgx_errlist[idx].sug);
      printf("Error: %s\n", sgx_errlist[idx].msg);
      break;
    }
  }

  if (idx == ttl)
    printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer "
           "Reference\" for more details.\n",
           ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  /* Call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL,
                           &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    print_error_message(ret);
    return -1;
  }

  return 0;
}

/* OCall functions */
void ocall_print_string(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[]) {
  (void)(argc);
  (void)(argv);

  int pid = -1;
  int pipefd[2], socketfd[2];
  if (pipe(pipefd) < 0) {
    printf("get pipe error");
    exit(1);
  }

  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socketfd) < 0) {
    printf("get socket error");
    exit(1);
  }

  int pagesize = getpagesize();
  int sgx_fd = -1;
  pid = fork();

  if (pid == 0) {
    // Child Process
    sgx_enclave_info_t einfo;
    read(pipefd[0], &einfo, sizeof(sgx_enclave_info_t));
    printf("Enclave ID: %lx\n", einfo.id);
    printf("Enclave Base Address: 0x%lx\n", einfo.start_addr);
    printf("Enclave Size: %lu\n", einfo.size);

    size_t pagebufsize = einfo.size / pagesize * sizeof(uint64_t);
    uint64_t *pagebuf = (uint64_t *)malloc(pagebufsize);
    if (pagebuf == NULL) {
      printf("[Child] pagebuffer allocation failed");
      exit(1);
    }

    if (read(pipefd[0], pagebuf, pagebufsize) != pagebufsize) {
      printf("[Child] pagebuffer reading failed");
      exit(1);
    }

    if ((sgx_fd = recv_fd(socketfd[0])) < 1) {
      printf("[Child] sgxfd reading failed");
      exit(1);
    }
    printf("[Child] SGX Device FD: %d\n", sgx_fd);

    if (map_self_virt(sgx_fd, (uint64_t)einfo.start_addr, einfo.size, pagebuf) != 0) {
      printf("[Child] remap enclave vm failed");
      exit(1);
    }

    if (SGX_SUCCESS != sgx_register_enclave(&einfo)) {
      printf("[Child] register enclave failed");
      exit(1);
    }
    if (SGX_SUCCESS != ecall_malloc_free(einfo.id)) {
      printf("[Child] ecall failed");
      exit(1);
    }
  } else {
    // Parent Process
    if (initialize_enclave() < 0) {
      printf("[Parent] initialize_enclave failed");
      exit(1);
    }
    sgx_enclave_info_t einfo;
    if (SGX_SUCCESS != sgx_get_enclave_info(global_eid, &einfo)) {
      printf("[Parent] get enclave info failed");
      exit(1);
    }

    sgx_fd = enclave_get_device_fd((void *)einfo.start_addr);
    printf("[Parent] SGX Device FD: %d\n", sgx_fd);

    if (send_fd(socketfd[1], sgx_fd) < 0) {
      printf("[Parent] sgx_fd write failed");
      exit(1);
    }

    if (SGX_SUCCESS != ecall_malloc_free(einfo.id)) {
      printf("[Parent] ecall failed");
      exit(1);
    }
    if (write(pipefd[1], &einfo, sizeof(sgx_enclave_info_t)) !=
        sizeof(sgx_enclave_info_t)) {
      printf("[Parent] enclave info write failed");
      exit(1);
    }

    size_t pagebufsize = einfo.size / pagesize * sizeof(uint64_t);
    uint64_t *pagebuf = (uint64_t *)malloc(pagebufsize);
    if (translate_self_virt((uint64_t)einfo.start_addr, einfo.size, pagebuf) <
        0) {
      printf("[Parent] translate virt failed");
      exit(1);
    }
    if (write(pipefd[1], pagebuf, pagebufsize) != pagebufsize) {
      printf("[Parent] send enclave mapping failed");
      exit(1);
    }
    printf("Enter a character before exit ...\n");
    getchar();

    sgx_destroy_enclave(global_eid);
  }

  return 0;
}
