#include "tracer_interface.h"
#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

#define PTA_TRACER_UUID { 0xd5a2471a, 0x3ae9, 0x11ec, \
                { 0x8d, 0x3d, 0x02, 0x42, 0xac, 0x13, 0x00, 0x03 } }

#define TRACER_CMD_CREATE  0x0
#define TRACER_CMD_CIV  0x1
#define TRACER_CMD_CFA  0x2
#define TRACER_CMD_PSLIST  0x3
#define TRACER_CMD_CONTROL_FLOW 0x4

int invoke_tracer_func(uint32_t reqID, void* buffer, size_t buflen, void* otherbuf, size_t otherbuflen, int reqPid) {
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
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = buffer; 
	op.params[0].tmpref.size = buflen;

	op.params[1].tmpref.buffer = otherbuf; 
	op.params[1].tmpref.size = otherbuflen;
	
	op.params[2].value.a = reqPid;

	res = TEEC_InvokeCommand(&sess, reqID, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	
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



void trace_control_flow(char* data) {
	invoke_tracer_func(TRACER_CMD_CONTROL_FLOW, NULL, 0, data, strlen(data)+1, 0);
}

void trace_cfa(int req_pid, uint64_t* stack_frames, int num_stack_frames, char* buffer, unsigned int buflen) {
	// tracer_cfa_args cfa_args = { .req_pid = req_pid, .stack_frames = stack_frames, .num_stack_frames = num_stack_frames, .buffer = buffer, .buflen = buflen };
	// invoke_tracer_func(TRACER_CMD_CFA, &cfa_args, sizeof(tracer_cfa_args));
	invoke_tracer_func(TRACER_CMD_CFA, buffer, buflen, stack_frames, num_stack_frames, req_pid);
}

void trace_civ(char* buffer, unsigned int buflen) {
	// tracer_civ_args civ_args = { .buffer = buffer, .buflen = buflen };	
	invoke_tracer_func(TRACER_CMD_CIV, buffer, buflen, NULL, 0, 0);
}

void create_tracer(char* req_buffer, unsigned int buflen) {
	invoke_tracer_func(TRACER_CMD_CREATE, req_buffer, buflen, NULL, 0, 0);
	// invoke_tracer_func(TRACER_CMD_CREATE, NULL, 0, NULL, 0, 0);
}

void trace_pslist() {
	invoke_tracer_func(TRACER_CMD_PSLIST, NULL, 0, NULL, 0, 0);
}
