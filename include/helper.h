#ifndef HELPER_H
#define HELPER_H

struct pio_metadata {
	PIO pio;
	unsigned int sm;
	unsigned int offset;
	pio_sm_config cfg;
	const pio_program_t *prog;
	bool inited;
};

void deinit(struct pio_metadata *inst)
{
	pio_sm_set_enabled(inst->pio, inst->sm, false);
	pio_remove_program(inst->pio, inst->prog, inst->offset);
	pio_sm_unclaim(inst->pio, inst->sm);
}

// TODO: deinit automatically when inited already

#endif // HELPER_H
