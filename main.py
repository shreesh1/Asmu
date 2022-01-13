from flask import Flask, request, render_template
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
# for accessing the RAX and RDI registers
from unicorn.x86_const import *
# We need to disassemble x86_64 code
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsError
from keystone import * 
app = Flask(__name__)


@app.route('/',methods=['GET','POST'])
def hello():
	emures = False
	if request.method == 'POST' and request.form.get("name"):
		form = request.form
		emures = emu_code(form)
	return render_template('home.html',emures=emures)

def emu_code(form):
	name =  request.form["name"]
	ks = Ks(KS_ARCH_X86, KS_MODE_64)
	asm_bytecode, _ = ks.asm(name)
	asm_bytecode = bytes(asm_bytecode)
	ADDRESS = 0x1000000
	try:
		mu = Uc(UC_ARCH_X86, UC_MODE_64)
		mu.mem_map(ADDRESS, 2 * 1024 * 1024)
		mu.mem_write(ADDRESS, asm_bytecode)
		mu.emu_start(ADDRESS, ADDRESS + len(asm_bytecode))
		rax = mu.reg_read(UC_X86_REG_RAX)
		rbx = mu.reg_read(UC_X86_REG_RBX)
		rcx = mu.reg_read(UC_X86_REG_RCX)
		rdx = mu.reg_read(UC_X86_REG_RDX)
		nl = '\n'
		return f"RAX = {rax} RBX = {rbx} RDX = {rdx} RCX = {rcx}"
	except UcError as e:
		print("Unicorn Error: %s" % e)


if __name__ == '__main__':
  app.run(host='0.0.0.0')
