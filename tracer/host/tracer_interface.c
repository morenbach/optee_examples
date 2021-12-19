#include "tracer_interface.h"
#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

#define PTA_TRACER_UUID { 0xd5a2471a, 0x3ae9, 0x11ec, \
                { 0x8d, 0x3d, 0x02, 0x42, 0xac, 0x13, 0x00, 0x03 } }

#define TRACER_CMD_CFA  0x0

#define CREATE_TRACER 0
#define TRACER_CIV    1
#define TRACER_CFA    2

typedef struct {
	int req_pid;
	uint64_t* stack_frames;
	int num_stack_frames;
	char* buffer;
	unsigned int buflen;
} tracer_cfa_args;

typedef struct {
	char* buffer;
	unsigned int buflen;
} tracer_civ_args;

int invoke_tracer_func(int reqID, void* priv_data, size_t priv_data_len) {
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = PTA_TRACER_UUID; 
	uint32_t err_origin;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = reqID; 
	op.params[1].tmpref.buffer = priv_data; 
	op.params[1].tmpref.size = priv_data_len;

	//printf("Invoking TA to increment 0x%x 0x%x\n", op.params[0].value.a, op.params[0].value.b);
	res = TEEC_InvokeCommand(&sess, TRACER_CMD_CFA, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	//printf("TA incremented value to 0x%lx\n", op.params[0].value.a);
	
	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}


void trace_cfa(int req_pid, uint64_t* stack_frames, int num_stack_frames, char* buffer, unsigned int buflen) {
	tracer_cfa_args cfa_args = { .req_pid = req_pid, .stack_frames = stack_frames, .num_stack_frames = num_stack_frames, .buffer = buffer, .buflen = buflen };
	invoke_tracer_func(TRACER_CFA, &cfa_args, sizeof(tracer_cfa_args));
}

void trace_civ(char* buffer, unsigned int buflen) {
	tracer_civ_args civ_args = { .buffer = buffer, .buflen = buflen };
	invoke_tracer_func(TRACER_CFA, &civ_args, sizeof(tracer_civ_args));
}

void create_tracer() {
	invoke_tracer_func(CREATE_TRACER, NULL, 0);
}