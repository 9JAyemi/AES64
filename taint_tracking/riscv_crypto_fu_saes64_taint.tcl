analyze -sv riscv_crypto_fu_saes64_taint.v

elaborate -top riscv_crypto_fu_saes64

clock g_clk
reset g_restn -non_resettable_regs 0


# check once the computation is finsihed that there is no 
# information leak to the registar where data is stored
assume {rs1_t == 1}
assert { !rd_t}


# Set the time limit to 1 hour (3600 seconds)
set_prove_time_limit 3600
prove -all