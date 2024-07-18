analyze -sv riscv_crypto_fu_saes64.v

elaborate -top riscv_crypto_fu_saes64

clock g_clk
reset g_resetn -non_resettable_regs 0

check_spv -create -from {valid rs1 rs2 enc_rcon op_saes64_ks1 op_saes64_ks2 op_saes64_imix op_saes64_encs op_saes64_encsm op_saes64_decs op_saes64_decsm} -to ready

# Set the time limit to 1 hour (3600 seconds)
set_prove_time_limit 3600
set_engine_mode Tri
prove -all