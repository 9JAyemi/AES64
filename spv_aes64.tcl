analyze -sv riscv_crypto_fu_saes64.v

elaborate -top riscv_crypto_fu_saes64

clock g_clk
reset g_resetn -non_resettable_regs 0

check_spv -create -from valid -to ready

# Set the time limit to 1 hour (3600 seconds)
set_prove_time_limit 3600
set_engine_mode Tri
prove -all