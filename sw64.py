from pwn import *

#registers probably 5 bit
v0 = 0
t0 = 1
t1 = 2
t2 = 3
t3 = 4
t4 = 5
t5 = 6
t6 = 7
t7 = 8
s0 = 9
s1 = 10
s2 = 11
s3 = 12
s4 = 13
s5 = 14
fp = 15
a0 = 16
a1 = 17
a2 = 18
a3 = 19
a4 = 20
a5 = 21
t8 = 22
t9 = 23
t10 = 24
t11 = 25
ra = 26
t12 = 27
at = 28
gp = 29
sp = 30
zero_reg = 31
unused_reg = 31

op_func = 0x10
op_ldw = 0x8
op_ldw_h = 0x9
op_stw = 0xa
op_ldq = 0x24
op_ldq_u = 0xb
op_stq = 0x2b
op_stq_u = 0x0f

func_add_l = 0
func_sub_l = 1
func_mul_l = 0x10
func_add_q = 0x08
func_sub_q = 0x09

op_call_pal = 0
pal_callsys = 0x83

def op_regs(opcode, function, d, rb, ra):
    inst = (opcode&(0x3f))<<26
    inst |= d&0x1f
    inst |= (function&0x3f)<<5
    inst |= (rb&0x1f)<<16
    inst |= (ra&0x1f)<<21
    return p32(inst)

def op_mem(opcode, ra, rb, mem_off):
    inst = (opcode&(0x3f))<<26
    inst |= (ra&0x1f)<<21
    inst |= (rb&0x1f)<<16
    inst |= mem_off&0xffff
    return p32(inst)

def pal(_pal):
    inst = (op_call_pal&0x3f)<<26
    inst |= _pal&0x1ffffff
    return p32(inst)

def mov(dest, src):
    return op_regs(op_func, func_add_q, dest, src, zero_reg)

def add(dest, r1, r2):
    return op_regs(op_func, func_add_q, dest, r1, r2)

def sub(dest, r1, r2):
    return op_regs(op_func, func_sub_q, dest, r1, r2)

def ldq(dest, r, off):
    return op_mem(op_ldq, dest, r, off)

def stq(src, r, off):
    return op_mem(op_stq, src, r, off)

#v0 syscall num
#a0-a5 args
def syscall_0():
    return pal(pal_callsys)