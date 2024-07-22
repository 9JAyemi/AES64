analyze -sv riscv_crypto_fu_saes64_taint.v

elaborate -top riscv_crypto_fu_saes64

clock g_clk
reset g_resetn -non_resettable_regs 0


# check once the computation is finsihed that there is no 
# information leak to the registar where data is stored
# assume {rs1_t == 1 && valid_t == 0 && rs2_t == 1 && enc_rcon_t == 0 && op_saes64_ks1_t == 0 && op_saes64_ks2_t == 0 && op_saes64_imix_t == 0 && op_saes64_encs_t == 0 && op_saes64_encsm_t == 0 && op_saes64_decs_t == 0 && op_saes64_decsm_t == 0}
# assume {valid_t == 1}
assert {rd_t == 0}
assert {ready_t == 0}


# Set the time limit to 1 hour (3600 seconds)
set_prove_time_limit 3600
set_engine_mode Tri
prove -all