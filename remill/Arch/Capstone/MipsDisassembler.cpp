#include "MipsDisassembler.h"

namespace remill {

struct MipsDisassembler::PrivateData final {
  std::size_t address_size;
};

MipsDisassembler::MipsDisassembler(bool is_64_bits)
    : CapstoneDisassembler(CS_ARCH_MIPS,
                           is_64_bits ? CS_MODE_MIPS64 : CS_MODE_MIPS32),
      d(new PrivateData) {
  d->address_size = (is_64_bits ? 64 : 32);
}

MipsDisassembler::~MipsDisassembler() {}

std::string MipsDisassembler::RegName(std::uintmax_t reg_id) const noexcept {
  return "";
}

bool MipsDisassembler::PostDisasmHook(const CapInstrPtr &cap_instr) const
    noexcept {
  return true;
}

bool MipsDisassembler::PostDecodeHook(
    const std::unique_ptr<Instruction> &rem_instr,
    const CapInstrPtr &cap_instr) const noexcept {
  return true;
}

bool MipsDisassembler::RegName(std::string &name, std::uintmax_t reg_id) const
    noexcept {
  name = RegName(reg_id);
  if (name.empty()) return false;

  return true;
}

bool MipsDisassembler::RegSize(std::size_t &size, const std::string &name) const
    noexcept {
  size = d->address_size;
  return true;
}

bool MipsDisassembler::InstrOps(std::vector<Operand> &op_list,
                                const CapInstrPtr &cap_instr) const noexcept {
  const cs_mips &instruction_details = cap_instr->detail->mips;

  for (std::uint8_t operand_index = 0;
       operand_index < instruction_details.op_count; operand_index++) {
    const auto &instruction_operand =
        instruction_details.operands[operand_index];

    if (instruction_operand.type == MIPS_OP_INVALID) break;

    Operand remill_operand = {};

    // registers
    if (instruction_operand.type == MIPS_OP_REG) {
      remill_operand.type = Operand::kTypeRegister;
      remill_operand.size = AddressSize() / 8;
      remill_operand.action = RegAccessType(instruction_operand.reg, cap_instr);

      remill_operand.reg.name = RegName(instruction_operand.reg);
      remill_operand.reg.size = remill_operand.size;

      // immediate values
    } else if (instruction_operand.type == MIPS_OP_IMM) {
      remill_operand.type = Operand::kTypeImmediate;
      remill_operand.size = AddressSize() / 8;
      remill_operand.action = Operand::kActionRead;

      remill_operand.imm.is_signed = true;
      remill_operand.imm.val = instruction_operand.imm;

      // memory addresses
    } else {
      remill_operand.type = Operand::kTypeAddress;
      remill_operand.size = AddressSize() / 8;

      if (operand_index == 0)
        remill_operand.action = Operand::kActionRead;
      else
        remill_operand.action = Operand::kActionWrite;

      remill_operand.addr.address_size = AddressSize() / 8;

      if (instruction_operand.mem.base != MIPS_REG_INVALID) {
        remill_operand.addr.base_reg.name =
            RegName(instruction_operand.mem.base);
        remill_operand.addr.base_reg.size = AddressSize() / 8;
      }

      remill_operand.addr.displacement = instruction_operand.mem.disp;
      remill_operand.addr.scale = 1;
      remill_operand.addr.kind = (remill_operand.action == Operand::kActionRead
                                      ? Operand::Address::kMemoryRead
                                      : Operand::Address::kMemoryWrite);
    }

    op_list.push_back(remill_operand);
  }

  return true;
}

std::size_t MipsDisassembler::AddressSize() const noexcept {
  return d->address_size;
}

Instruction::Category MipsDisassembler::InstrCategory(
    const CapInstrPtr &cap_instr) const noexcept {
  /*
    The following opcodes were found in the MIPS architecture manual but were
    not
    inside the Capstone definitions; some of them have probably combined names
    (i.e.: fmt ones)
    and it's just a matter of getting a closer look at the documentation

    ABS.fmt
    ADD.fmt
    ALNV.PS
    C.cond.fmt
    CACHEE
    CEIL.L.fmt
    CEIL.W.fmt
    CFC2
    CLASS.fmt
    COP2
    CTC2
    CVT.D.fmt
    CVT.L.fmt
    CVT.PS.S
    CVT.S.PL
    CVT.S.PU
    CVT.S.fmt
    CVT.W.fmt
    DIV.fmt
    DVP
    ERETNC
    EVP
    FLOOR.L.fmt
    FLOOR.W.fmt
    LBE
    LBUE
    LHE
    LHUE
    LLE
    LLDP
    LLWP
    LLWPE
    LWE
    LWLE
    LWRE
    MADD.fmt
    MADDF.fmt
    MSUBF.fmt
    MAX.fmt
    MIN.fmt
    MAXA.fmt
    MINA.fmt
    MFHC0
    MFHC2
    MOV.fmt
    MOVF.fmt
    MOVN.fmt
    MOVT.fmt
    MOVZ.fmt
    MSUB.fmt
    MTHC0
    MTHC2
    MUL.fmt
    NAL
    NEG.fmt
    NMADD.fmt
    NMSUB.fmt
    PLL.PS
    PLU.PS
    PREFE
    PREFX
    PUL.PS
    PUU.PS
    RDPGPR
    RECIP.fmt
    RINT.fmt
    ROUND.L.fmt
    ROUND.W.fmt
    RSQRT.fmt
    SBE
    SCDP
    SCE
    SCWP
    SCWPE
    SEL.fmt
    SELEQZ.fmt
    SELNEQZ.fmt
    SHE
    SIGRIE
    SQRT.fmt
    SUB.fmt
    SWE
    SWLE
    SWRE
    SYNCI
    TLBINV
    TLBINVF
    TRUNC.L.fmt
    TRUNC.W.fmt
    WRPGPR
  */

  Instruction::Category category = {};

  // use the same sorting as the manual!
  switch (cap_instr->id) {
    case MIPS_INS_ABS:
    case MIPS_INS_ADD:
    case MIPS_INS_ADDI:
    case MIPS_INS_ADDIU:
    case MIPS_INS_ADDIUPC:
    case MIPS_INS_ADDU:
    case MIPS_INS_ALIGN:
    case MIPS_INS_DALIGN:
    case MIPS_INS_ALUIPC:
    case MIPS_INS_AND:
    case MIPS_INS_ANDI:
    case MIPS_INS_AUI:
    case MIPS_INS_DAUI:
    case MIPS_INS_DAHI:
    case MIPS_INS_DATI:
    case MIPS_INS_AUIPC:
    case MIPS_INS_B:
    case MIPS_INS_BAL:
    case MIPS_INS_BALC:
    case MIPS_INS_BC:
    case MIPS_INS_BC1EQZ:
    case MIPS_INS_BC1NEZ:
    case MIPS_INS_BC1F:
    case MIPS_INS_BC1FL:
    case MIPS_INS_BC1T:
    case MIPS_INS_BC1TL:
    case MIPS_INS_BC2EQZ:
    case MIPS_INS_BC2NEZ:
    case MIPS_INS_BC2F:
    case MIPS_INS_BC2FL:
    case MIPS_INS_BC2T:
    case MIPS_INS_BC2TL:
    case MIPS_INS_BEQ:
    case MIPS_INS_BEQL:
    case MIPS_INS_BGEZ:
    case MIPS_INS_BGEZAL:

    // start of B<cond>C
    case MIPS_INS_BLEZALC:
    case MIPS_INS_BGEZALC:
    case MIPS_INS_BGTZALC:
    case MIPS_INS_BLTZALC:
    case MIPS_INS_BEQZALC:
    case MIPS_INS_BNEZALC:
    case MIPS_INS_BGEZALL:
    case MIPS_INS_BLEZC:
    case MIPS_INS_BGEZC:
    case MIPS_INS_BGEC:
    case MIPS_INS_BGTZC:
    case MIPS_INS_BLTZC:
    case MIPS_INS_BLTC:
    case MIPS_INS_BGEUC:
    case MIPS_INS_BLTUC:
    case MIPS_INS_BEQC:
    case MIPS_INS_BNEC:
    case MIPS_INS_BEQZC:
    case MIPS_INS_BNEZC:
    // end of B<cond>C

    case MIPS_INS_BGEZL:
    case MIPS_INS_BGTZ:
    case MIPS_INS_BGTZL:
    case MIPS_INS_BITSWAP:
    case MIPS_INS_DBITSWAP:
    case MIPS_INS_BLEZ:
    case MIPS_INS_BLEZL:
    case MIPS_INS_BLTZ:
    case MIPS_INS_BLTZAL:
    case MIPS_INS_BLTZALL:
    case MIPS_INS_BLTZL:
    case MIPS_INS_BNE:
    case MIPS_INS_BNEL:
    case MIPS_INS_BOVC:
    case MIPS_INS_BNVC:
    case MIPS_INS_BREAK:
    case MIPS_INS_CACHE:
    case MIPS_INS_CFC1:
    case MIPS_INS_CLO:
    case MIPS_INS_CLZ:

    // start of CMP.condn.fmt
    case MIPS_INS_FCAF:
    case MIPS_INS_FCUN:
    case MIPS_INS_FCEQ:
    case MIPS_INS_FCUEQ:
    case MIPS_INS_FCLT:
    case MIPS_INS_FCULT:
    case MIPS_INS_FCLE:
    case MIPS_INS_FCULE:
    case MIPS_INS_FSAF:
    case MIPS_INS_FSUN:
    case MIPS_INS_FSEQ:
    case MIPS_INS_FSUEQ:
    case MIPS_INS_FSLT:
    case MIPS_INS_FSULT:
    case MIPS_INS_FSLE:
    case MIPS_INS_FSULE:
    // end of CMP.condn.fmt

    case MIPS_INS_CTC1:
    case MIPS_INS_DADD:
    case MIPS_INS_DADDI:
    case MIPS_INS_DADDIU:
    case MIPS_INS_DADDU:
    case MIPS_INS_DCLO:
    case MIPS_INS_DCLZ:
    case MIPS_INS_DERET:
    case MIPS_INS_DEXT:
    case MIPS_INS_DEXTM:
    case MIPS_INS_DEXTU:
    case MIPS_INS_DI:
    case MIPS_INS_DINS:
    case MIPS_INS_DINSM:
    case MIPS_INS_DINSU:
    case MIPS_INS_DIV:
    case MIPS_INS_MOD:
    case MIPS_INS_DIVU:
    case MIPS_INS_MODU:
    case MIPS_INS_DDIV:
    case MIPS_INS_DMOD:
    case MIPS_INS_DDIVU:
    case MIPS_INS_DMODU:
    case MIPS_INS_DMFC0:
    case MIPS_INS_DMFC1:
    case MIPS_INS_DMFC2:
    case MIPS_INS_DMTC0:
    case MIPS_INS_DMTC1:
    case MIPS_INS_DMTC2:
    case MIPS_INS_DMULT:
    case MIPS_INS_DMULTU:
    case MIPS_INS_DROTR:
    case MIPS_INS_DROTR32:
    case MIPS_INS_DROTRV:
    case MIPS_INS_DSBH:
    case MIPS_INS_DSHD:
    case MIPS_INS_DSLL:
    case MIPS_INS_DSLL32:
    case MIPS_INS_DSLLV:
    case MIPS_INS_DSRA:
    case MIPS_INS_DSRA32:
    case MIPS_INS_DSRAV:
    case MIPS_INS_DSRL:
    case MIPS_INS_DSRL32:
    case MIPS_INS_DSRLV:
    case MIPS_INS_DSUB:
    case MIPS_INS_DSUBU:
    case MIPS_INS_EHB:
    case MIPS_INS_EI:
    case MIPS_INS_ERET:
    case MIPS_INS_EXT:
    case MIPS_INS_INS:
    case MIPS_INS_J: {
      category = Instruction::kCategoryNormal;
      break;
    }

    case MIPS_INS_JAL: {
      category = Instruction::kCategoryDirectFunctionCall;
      break;
    }

    case MIPS_INS_JALR:
    case MIPS_INS_JALR_HB:
    case MIPS_INS_JALX:
    case MIPS_INS_JIALC:
    case MIPS_INS_JIC: {
      category = Instruction::kCategoryNormal;
      break;
    }

    case MIPS_INS_JR: {
      category = Instruction::kCategoryFunctionReturn;
      break;
    }

    case MIPS_INS_JR_HB:
    case MIPS_INS_LB:
    case MIPS_INS_LBU:
    case MIPS_INS_LD:
    case MIPS_INS_LDC1:
    case MIPS_INS_LDC2:
    case MIPS_INS_LDL:
    case MIPS_INS_LDPC:
    case MIPS_INS_LDR:
    case MIPS_INS_LDXC1:
    case MIPS_INS_LH:
    case MIPS_INS_LHU:
    case MIPS_INS_LL:
    case MIPS_INS_LLD:
    case MIPS_INS_DLSA:
    case MIPS_INS_LSA:
    case MIPS_INS_LUI:
    case MIPS_INS_LUXC1:
    case MIPS_INS_LW:
    case MIPS_INS_LWC1:
    case MIPS_INS_LWC2:
    case MIPS_INS_LWL:
    case MIPS_INS_LWPC:
    case MIPS_INS_LWR:
    case MIPS_INS_LWU:
    case MIPS_INS_LWUPC:
    case MIPS_INS_LWXC1:
    case MIPS_INS_MADD:
    case MIPS_INS_MADDU:
    case MIPS_INS_MFC0:
    case MIPS_INS_MFC1:
    case MIPS_INS_MFC2:
    case MIPS_INS_MFHC1:
    case MIPS_INS_MFHI:
    case MIPS_INS_MFLO:
    case MIPS_INS_MOVF:
    case MIPS_INS_MOVN:
    case MIPS_INS_MOVT:
    case MIPS_INS_MOVZ:
    case MIPS_INS_MSUB:
    case MIPS_INS_MSUBU:
    case MIPS_INS_MTC0:
    case MIPS_INS_MTC1:
    case MIPS_INS_MTC2:
    case MIPS_INS_MTHC1:
    case MIPS_INS_MTHI:
    case MIPS_INS_MTLO:
    case MIPS_INS_MUL:
    case MIPS_INS_MUH:
    case MIPS_INS_MULU:
    case MIPS_INS_MUHU:
    case MIPS_INS_DMUL:
    case MIPS_INS_DMUH:
    case MIPS_INS_DMULU:
    case MIPS_INS_DMUHU:
    case MIPS_INS_MULT:
    case MIPS_INS_MULTU:
    case MIPS_INS_NOP:
    case MIPS_INS_NOR:
    case MIPS_INS_OR:
    case MIPS_INS_ORI:
    case MIPS_INS_PAUSE:
    case MIPS_INS_PREF:
    case MIPS_INS_RDHWR:
    case MIPS_INS_ROTR:
    case MIPS_INS_ROTRV:
    case MIPS_INS_SB:
    case MIPS_INS_SC:
    case MIPS_INS_SCD:
    case MIPS_INS_SD:
    case MIPS_INS_SDBBP:
    case MIPS_INS_SDC1:
    case MIPS_INS_SDC2:
    case MIPS_INS_SDL:
    case MIPS_INS_SDR:
    case MIPS_INS_SDXC1:
    case MIPS_INS_SEB:
    case MIPS_INS_SEH:
    case MIPS_INS_SELEQZ:
    case MIPS_INS_SELNEZ:
    case MIPS_INS_SH:
    case MIPS_INS_SLL:
    case MIPS_INS_SLLV:
    case MIPS_INS_SLT:
    case MIPS_INS_SLTI:
    case MIPS_INS_SLTIU:
    case MIPS_INS_SLTU:
    case MIPS_INS_SRA:
    case MIPS_INS_SRAV:
    case MIPS_INS_SRL:
    case MIPS_INS_SRLV:
    case MIPS_INS_SSNOP:
    case MIPS_INS_SUB:
    case MIPS_INS_SUBU:
    case MIPS_INS_SUXC1:
    case MIPS_INS_SW:
    case MIPS_INS_SWC1:
    case MIPS_INS_SWC2:
    case MIPS_INS_SWL:
    case MIPS_INS_SWR:
    case MIPS_INS_SWXC1:
    case MIPS_INS_SYNC:
    case MIPS_INS_SYSCALL:
    case MIPS_INS_TEQ:
    case MIPS_INS_TEQI:
    case MIPS_INS_TGE:
    case MIPS_INS_TGEI:
    case MIPS_INS_TGEIU:
    case MIPS_INS_TGEU:
    case MIPS_INS_TLBP:
    case MIPS_INS_TLBR:
    case MIPS_INS_TLBWI:
    case MIPS_INS_TLBWR:
    case MIPS_INS_TLT:
    case MIPS_INS_TLTI:
    case MIPS_INS_TLTIU:
    case MIPS_INS_TLTU:
    case MIPS_INS_TNE:
    case MIPS_INS_TNEI:
    case MIPS_INS_WAIT:
    case MIPS_INS_WSBH:
    case MIPS_INS_XOR:
    case MIPS_INS_XORI:
      category = Instruction::kCategoryNormal;

    /*
      i couldn't find these opcodes in the manual; some of them can probably
      traced to
      known instructions with variable encoding (i.e.: .fmt notation)
    */

    case MIPS_INS_ABSQ_S:
    case MIPS_INS_ADDQH:
    case MIPS_INS_ADDQH_R:
    case MIPS_INS_ADDQ:
    case MIPS_INS_ADDQ_S:
    case MIPS_INS_ADDSC:
    case MIPS_INS_ADDS_A:
    case MIPS_INS_ADDS_S:
    case MIPS_INS_ADDS_U:
    case MIPS_INS_ADDUH:
    case MIPS_INS_ADDUH_R:
    case MIPS_INS_ADDU_S:
    case MIPS_INS_ADDVI:
    case MIPS_INS_ADDV:
    case MIPS_INS_ADDWC:
    case MIPS_INS_ADD_A:
    case MIPS_INS_APPEND:
    case MIPS_INS_ASUB_S:
    case MIPS_INS_ASUB_U:
    case MIPS_INS_AVER_S:
    case MIPS_INS_AVER_U:
    case MIPS_INS_AVE_S:
    case MIPS_INS_AVE_U:
    case MIPS_INS_BADDU:
    case MIPS_INS_BALIGN:
    case MIPS_INS_BC0F:
    case MIPS_INS_BC0FL:
    case MIPS_INS_BC0T:
    case MIPS_INS_BC0TL:
    case MIPS_INS_BC3F:
    case MIPS_INS_BC3FL:
    case MIPS_INS_BC3T:
    case MIPS_INS_BC3TL:
    case MIPS_INS_BCLRI:
    case MIPS_INS_BCLR:
    case MIPS_INS_BGEZALS:
    case MIPS_INS_BINSLI:
    case MIPS_INS_BINSL:
    case MIPS_INS_BINSRI:
    case MIPS_INS_BINSR:
    case MIPS_INS_BITREV:
    case MIPS_INS_BLTZALS:
    case MIPS_INS_BMNZI:
    case MIPS_INS_BMNZ:
    case MIPS_INS_BMZI:
    case MIPS_INS_BMZ:
    case MIPS_INS_BNEGI:
    case MIPS_INS_BNEG:
    case MIPS_INS_BNZ:
    case MIPS_INS_BPOSGE32:
    case MIPS_INS_BSELI:
    case MIPS_INS_BSEL:
    case MIPS_INS_BSETI:
    case MIPS_INS_BSET:
    case MIPS_INS_BZ:
    case MIPS_INS_BEQZ:
    case MIPS_INS_BNEZ:
    case MIPS_INS_BTEQZ:
    case MIPS_INS_BTNEZ:
    case MIPS_INS_CEIL:
    case MIPS_INS_CEQI:
    case MIPS_INS_CEQ:
    case MIPS_INS_CFCMSA:
    case MIPS_INS_CINS:
    case MIPS_INS_CINS32:
    case MIPS_INS_CLASS:
    case MIPS_INS_CLEI_S:
    case MIPS_INS_CLEI_U:
    case MIPS_INS_CLE_S:
    case MIPS_INS_CLE_U:
    case MIPS_INS_CLTI_S:
    case MIPS_INS_CLTI_U:
    case MIPS_INS_CLT_S:
    case MIPS_INS_CLT_U:
    case MIPS_INS_CMPGDU:
    case MIPS_INS_CMPGU:
    case MIPS_INS_CMPU:
    case MIPS_INS_CMP:
    case MIPS_INS_COPY_S:
    case MIPS_INS_COPY_U:
    case MIPS_INS_CTCMSA:
    case MIPS_INS_CVT:
    case MIPS_INS_C:
    case MIPS_INS_CMPI:
    case MIPS_INS_DIV_S:
    case MIPS_INS_DIV_U:
    case MIPS_INS_DOTP_S:
    case MIPS_INS_DOTP_U:
    case MIPS_INS_DPADD_S:
    case MIPS_INS_DPADD_U:
    case MIPS_INS_DPAQX_SA:
    case MIPS_INS_DPAQX_S:
    case MIPS_INS_DPAQ_SA:
    case MIPS_INS_DPAQ_S:
    case MIPS_INS_DPAU:
    case MIPS_INS_DPAX:
    case MIPS_INS_DPA:
    case MIPS_INS_DPOP:
    case MIPS_INS_DPSQX_SA:
    case MIPS_INS_DPSQX_S:
    case MIPS_INS_DPSQ_SA:
    case MIPS_INS_DPSQ_S:
    case MIPS_INS_DPSUB_S:
    case MIPS_INS_DPSUB_U:
    case MIPS_INS_DPSU:
    case MIPS_INS_DPSX:
    case MIPS_INS_DPS:
    case MIPS_INS_EXTP:
    case MIPS_INS_EXTPDP:
    case MIPS_INS_EXTPDPV:
    case MIPS_INS_EXTPV:
    case MIPS_INS_EXTRV_RS:
    case MIPS_INS_EXTRV_R:
    case MIPS_INS_EXTRV_S:
    case MIPS_INS_EXTRV:
    case MIPS_INS_EXTR_RS:
    case MIPS_INS_EXTR_R:
    case MIPS_INS_EXTR_S:
    case MIPS_INS_EXTR:
    case MIPS_INS_EXTS:
    case MIPS_INS_EXTS32:
    case MIPS_INS_FADD:
    case MIPS_INS_FCLASS:
    case MIPS_INS_FCNE:
    case MIPS_INS_FCOR:
    case MIPS_INS_FCUNE:
    case MIPS_INS_FDIV:
    case MIPS_INS_FEXDO:
    case MIPS_INS_FEXP2:
    case MIPS_INS_FEXUPL:
    case MIPS_INS_FEXUPR:
    case MIPS_INS_FFINT_S:
    case MIPS_INS_FFINT_U:
    case MIPS_INS_FFQL:
    case MIPS_INS_FFQR:
    case MIPS_INS_FILL:
    case MIPS_INS_FLOG2:
    case MIPS_INS_FLOOR:
    case MIPS_INS_FMADD:
    case MIPS_INS_FMAX_A:
    case MIPS_INS_FMAX:
    case MIPS_INS_FMIN_A:
    case MIPS_INS_FMIN:
    case MIPS_INS_MOV:
    case MIPS_INS_FMSUB:
    case MIPS_INS_FMUL:
    case MIPS_INS_NEG:
    case MIPS_INS_FRCP:
    case MIPS_INS_FRINT:
    case MIPS_INS_FRSQRT:
    case MIPS_INS_FSNE:
    case MIPS_INS_FSOR:
    case MIPS_INS_FSQRT:
    case MIPS_INS_SQRT:
    case MIPS_INS_FSUB:
    case MIPS_INS_FSUNE:
    case MIPS_INS_FTINT_S:
    case MIPS_INS_FTINT_U:
    case MIPS_INS_FTQ:
    case MIPS_INS_FTRUNC_S:
    case MIPS_INS_FTRUNC_U:
    case MIPS_INS_HADD_S:
    case MIPS_INS_HADD_U:
    case MIPS_INS_HSUB_S:
    case MIPS_INS_HSUB_U:
    case MIPS_INS_ILVEV:
    case MIPS_INS_ILVL:
    case MIPS_INS_ILVOD:
    case MIPS_INS_ILVR:
    case MIPS_INS_INSERT:
    case MIPS_INS_INSV:
    case MIPS_INS_INSVE:
    case MIPS_INS_JALRS:
    case MIPS_INS_JALS:
    case MIPS_INS_JRADDIUSP:
    case MIPS_INS_JRC:
    case MIPS_INS_JALRC:
    case MIPS_INS_LBUX:
    case MIPS_INS_LDC3:
    case MIPS_INS_LDI:
    case MIPS_INS_LHX:
    case MIPS_INS_LWC3:
    case MIPS_INS_LWX:
    case MIPS_INS_LI:
    case MIPS_INS_MADDF:
    case MIPS_INS_MADDR_Q:
    case MIPS_INS_MADDV:
    case MIPS_INS_MADD_Q:
    case MIPS_INS_MAQ_SA:
    case MIPS_INS_MAQ_S:
    case MIPS_INS_MAXA:
    case MIPS_INS_MAXI_S:
    case MIPS_INS_MAXI_U:
    case MIPS_INS_MAX_A:
    case MIPS_INS_MAX:
    case MIPS_INS_MAX_S:
    case MIPS_INS_MAX_U:
    case MIPS_INS_MINA:
    case MIPS_INS_MINI_S:
    case MIPS_INS_MINI_U:
    case MIPS_INS_MIN_A:
    case MIPS_INS_MIN:
    case MIPS_INS_MIN_S:
    case MIPS_INS_MIN_U:
    case MIPS_INS_MODSUB:
    case MIPS_INS_MOD_S:
    case MIPS_INS_MOD_U:
    case MIPS_INS_MOVE:
    case MIPS_INS_MSUBF:
    case MIPS_INS_MSUBR_Q:
    case MIPS_INS_MSUBV:
    case MIPS_INS_MSUB_Q:
    case MIPS_INS_MTHLIP:
    case MIPS_INS_MTM0:
    case MIPS_INS_MTM1:
    case MIPS_INS_MTM2:
    case MIPS_INS_MTP0:
    case MIPS_INS_MTP1:
    case MIPS_INS_MTP2:
    case MIPS_INS_MULEQ_S:
    case MIPS_INS_MULEU_S:
    case MIPS_INS_MULQ_RS:
    case MIPS_INS_MULQ_S:
    case MIPS_INS_MULR_Q:
    case MIPS_INS_MULSAQ_S:
    case MIPS_INS_MULSA:
    case MIPS_INS_MULV:
    case MIPS_INS_MUL_Q:
    case MIPS_INS_MUL_S:
    case MIPS_INS_NLOC:
    case MIPS_INS_NLZC:
    case MIPS_INS_NMADD:
    case MIPS_INS_NMSUB:
    case MIPS_INS_NORI:
    case MIPS_INS_NOT:
    case MIPS_INS_PACKRL:
    case MIPS_INS_PCKEV:
    case MIPS_INS_PCKOD:
    case MIPS_INS_PCNT:
    case MIPS_INS_PICK:
    case MIPS_INS_POP:
    case MIPS_INS_PRECEQU:
    case MIPS_INS_PRECEQ:
    case MIPS_INS_PRECEU:
    case MIPS_INS_PRECRQU_S:
    case MIPS_INS_PRECRQ:
    case MIPS_INS_PRECRQ_RS:
    case MIPS_INS_PRECR:
    case MIPS_INS_PRECR_SRA:
    case MIPS_INS_PRECR_SRA_R:
    case MIPS_INS_PREPEND:
    case MIPS_INS_RADDU:
    case MIPS_INS_RDDSP:
    case MIPS_INS_REPLV:
    case MIPS_INS_REPL:
    case MIPS_INS_RINT:
    case MIPS_INS_ROUND:
    case MIPS_INS_SAT_S:
    case MIPS_INS_SAT_U:
    case MIPS_INS_SDC3:
    case MIPS_INS_SEL:
    case MIPS_INS_SEQ:
    case MIPS_INS_SEQI:
    case MIPS_INS_SHF:
    case MIPS_INS_SHILO:
    case MIPS_INS_SHILOV:
    case MIPS_INS_SHLLV:
    case MIPS_INS_SHLLV_S:
    case MIPS_INS_SHLL:
    case MIPS_INS_SHLL_S:
    case MIPS_INS_SHRAV:
    case MIPS_INS_SHRAV_R:
    case MIPS_INS_SHRA:
    case MIPS_INS_SHRA_R:
    case MIPS_INS_SHRLV:
    case MIPS_INS_SHRL:
    case MIPS_INS_SLDI:
    case MIPS_INS_SLD:
    case MIPS_INS_SLLI:
    case MIPS_INS_SNE:
    case MIPS_INS_SNEI:
    case MIPS_INS_SPLATI:
    case MIPS_INS_SPLAT:
    case MIPS_INS_SRAI:
    case MIPS_INS_SRARI:
    case MIPS_INS_SRAR:
    case MIPS_INS_SRLI:
    case MIPS_INS_SRLRI:
    case MIPS_INS_SRLR:
    case MIPS_INS_ST:
    case MIPS_INS_SUBQH:
    case MIPS_INS_SUBQH_R:
    case MIPS_INS_SUBQ:
    case MIPS_INS_SUBQ_S:
    case MIPS_INS_SUBSUS_U:
    case MIPS_INS_SUBSUU_S:
    case MIPS_INS_SUBS_S:
    case MIPS_INS_SUBS_U:
    case MIPS_INS_SUBUH:
    case MIPS_INS_SUBUH_R:
    case MIPS_INS_SUBU_S:
    case MIPS_INS_SUBVI:
    case MIPS_INS_SUBV:
    case MIPS_INS_SWC3:
    case MIPS_INS_TRUNC:
    case MIPS_INS_V3MULU:
    case MIPS_INS_VMM0:
    case MIPS_INS_VMULU:
    case MIPS_INS_VSHF:
    case MIPS_INS_WRDSP:
    case MIPS_INS_NEGU:
      category = Instruction::kCategoryInvalid;
  }

  return category;
}

}  //  namespace remill
