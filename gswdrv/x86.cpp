//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2003-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "hin.h"
#include "x86.h"

#ifdef A
#undef A
#endif
#ifdef C
#undef C
#endif
#ifdef D
#undef D
#endif
#ifdef E
#undef E
#endif
#ifdef F
#undef F
#endif
#ifdef G
#undef G
#endif
#ifdef I
#undef I
#endif
#ifdef J
#undef J
#endif
#ifdef M
#undef M
#endif
#ifdef O
#undef O
#endif
#ifdef P
#undef P
#endif
#ifdef PR
#undef PR
#endif
#ifdef Q
#undef Q
#endif
#ifdef R
#undef R
#endif
#ifdef S
#undef S
#endif
#ifdef T
#undef T
#endif
#ifdef V
#undef V
#endif
#ifdef VR
#undef VR
#endif
#ifdef W
#undef W
#endif
#ifdef X
#undef X
#endif
#ifdef Y
#undef Y
#endif
#ifdef SH
#undef SH
#endif
#ifdef a
#undef a
#endif
#ifdef b
#undef b
#endif
#ifdef d
#undef d
#endif
#ifdef dq
#undef dq
#endif
#ifdef p
#undef p
#endif
#ifdef pd
#undef pd
#endif
#ifdef pi
#undef pi
#endif
#ifdef ps
#undef ps
#endif
#ifdef q
#undef q
#endif
#ifdef s
#undef s
#endif
#ifdef sd
#undef sd
#endif
#ifdef si
#undef si
#endif
#ifdef ss
#undef ss
#endif
#ifdef v
#undef v
#endif
#ifdef w
#undef w
#endif
#ifdef z
#undef z
#endif
#ifdef sn
#undef sn
#endif


#define A				0x00100
#define C				0x00200
#define D				0x00300
#define E				0x00400
#define F				0x00500
#define G				0x00600
#define I				0x00700
#define J				0x00800
#define M				0x00900
#define O				0x00a00
#define P				0x00b00
#define PR				0x00c00
#define Q				0x00d00
#define R				0x00e00
#define S				0x00f00
#define T				0x01000
#define V				0x01100
#define VR				0x01200
#define W				0x01300
#define X				0x01400
#define Y				0x01500

#define SH				0xfff00

#define a				|0x01
#define b				|0x02
#define d				|0x03
#define dq				|0x04
#define p				|0x05
#define pd				|0x06
#define pi				|0x07
#define ps				|0x08
#define q				|0x09
#define s				|0x0a
#define sd				|0x0b
#define si				|0x0c
#define ss				|0x0d
#define v				|0x0e
#define w				|0x0f
#define z				|0x10
#define sn				|0x11

#define INS_ESCAPE				(0x00000001)
#define INS_PREFIX				(0x00000002)
#define INS_REX_PREFIX			(0x00000004)
#define INS_OPSIZE_PREFIX		(0x00000008)
#define INS_ADSIZE_PREFIX		(0x00000010)
#define INS_GROUP				(0x00000020)
#define INS_INVALID				(0x00000040)
#define INS_3DNOW_CODING		(0x00000080)
#define INS_64VALUE				(0x00000100)
#define INS_REX_W				(0x00000200)
#define INS_RET					(0x00000400)


namespace x86 {

	struct InstructionInfo {
		BYTE OpCode;
		ULONG Flags;
		ULONG Params[3];
		InstructionInfo *Escape;
	};

	InstructionInfo Gr16OpCode[] = {
		{0x0, 0, /* FXSAVE */{M, 0, 0}, NULL },
		{0x1, 0, /* FXRSTOR */{M, 0, 0}, NULL },
		{0x2, 0, /* LDMXCSR */{M d, 0, 0}, NULL },
		{0x3, 0, /* STMXCSR */{M d, 0, 0}, NULL },
		{0x4, INS_INVALID, {0, 0, 0}, NULL },
		{0x5, 0, /* LFENCE */{0, 0, 0}, NULL },
		{0x6, 0, /* MFENCE */{0, 0, 0}, NULL },
		{0x7, 0, /* SFENCE */{0, 0, 0}, NULL }
	};

	InstructionInfo TbOpCode[] = {
		{0x00, INS_GROUP, /* group #6 */{M, 0, 0}, NULL },
		{0x01, INS_GROUP, /* group #7 */{M, 0, 0}, NULL },
		{0x02, 0, /* LAR */{G v, E w, 0}, NULL },
		{0x03, 0, /* LSL */{G v, E w, 0}, NULL },
		{0x04, 0, /* LOADALL? RESET? HANG? (80286) */{0, 0, 0}, NULL },
		{0x05, 0, /* LOADALL (80286) SYSCALL (AMD) */{0, 0, 0}, NULL },
		{0x06, 0, /* CLTS */{0, 0, 0}, NULL },
		{0x07, 0, /* LOADALL (80386) SYSRET (AMD) */{0, 0, 0}, NULL },
		{0x08, 0, /* INVD */{0, 0, 0}, NULL },
		{0x09, 0, /* WBINVD */{0, 0, 0}, NULL },
		{0x0a, INS_INVALID, {0, 0, 0}, NULL },
		{0x0b, 0, /* UD1 */{0, 0, 0}, NULL },
		{0x0c, INS_INVALID, {0, 0, 0}, NULL },
		{0x0d, INS_GROUP, /* 3DNow! PREFETCHx*/{M, 0, 0}, NULL },
		{0x0e, INS_GROUP, /* 3DNow! FEMMS*/{0, 0, 0}, NULL },
		{0x0f, INS_GROUP | INS_3DNOW_CODING, /* 3DNow! */{M, 0, 0}, NULL },
		{0x10, 0, /* UMOV MOVUPS MOVSS MOVUPD MOVSD */{E b, G b, 0}, NULL },
		{0x11, 0, /* UMOV MOVUPS MOVSS MOVUPD MOVSD */{E v, G v, 0}, NULL },
		{0x12, 0, /* UMOV MOVLPS MOVSLDUP MOVLPD MOVDDUP*/{G b, E b, 0}, NULL },
		{0x13, 0, /* UMOV MOVLPS MOVLPD */{G v, E v, 0}, NULL },
		{0x14, 0, /* UNPCKLPS UNPCKLPD*/{V ps, W q, 0}, NULL },
		{0x15, 0, /* UNPCKHPS UNPCKHPD */{V ps, W ps, 0}, NULL },
		{0x16, 0, /* MOVHPS MOVSHDUP MOVHPD*/{V q, M q, 0}, NULL },
		{0x17, 0, /* MOVHPS MOVHPD */{M q, V q, 0}, NULL },
		{0x18, INS_GROUP, /* group #17 */{M, 0, 0}, NULL },
		{0x19, 0, /* HINT_NOP */{M, 0, 0}, NULL },
		{0x1a, 0, /* HINT_NOP */{M, 0, 0}, NULL },
		{0x1b, 0, /* HINT_NOP */{M, 0, 0}, NULL },
		{0x1c, 0, /* HINT_NOP */{M, 0, 0}, NULL },
		{0x1d, 0, /* HINT_NOP */{M, 0, 0}, NULL },
		{0x1e, 0, /* HINT_NOP */{M, 0, 0}, NULL },
		{0x1f, 0, /* HINT_NOP */{M, 0, 0}, NULL },
		{0x20, 0, /* MOV */{R d, C d, 0}, NULL },
		{0x21, 0, /* MOV */{R d, D d, 0}, NULL },
		{0x22, 0, /* MOV */{C d, R d, 0}, NULL },
		{0x23, 0, /* MOV */{D d, R d, 0}, NULL },
		{0x24, 0, /* MOV */{R d, T d, 0}, NULL },
		{0x25, INS_INVALID, {0, 0, 0}, NULL },
		{0x26, 0, /* MOV */{T d, R d, 0}, NULL },
		{0x27, INS_INVALID, {0, 0, 0}, NULL },
		{0x28, 0, /* MOVAPS MOVAPD */{V ps, W ps, 0}, NULL },
		{0x29, 0, /* MOVAPS MOVAPD */{W ps, V ps, 0}, NULL },
		{0x2a, 0, /* CVTPI2PS CVTSI2SS CVTPI2PD CVTSI2SD */{V q, M q, 0}, NULL },
		{0x2b, 0, /* MOVNTPS MOVNTPD */{M ps, V ps, 0}, NULL },
		{0x2c, 0, /* CVTTPS2PI CVTTSS2SI CVTTPD2PI CVTTSD2SI */{P, W, 0}, NULL },
		{0x2d, 0, /* CVTPS2PI CVTSS2SI CVTPD2PI CVTSD2SI */{P, W, 0}, NULL },
		{0x2e, 0, /* UCOMISD */{V q, W q, 0}, NULL },
		{0x2f, 0, /* COMISD */{V q, W q, 0}, NULL },
		{0x30, 0, /* WRMSR */{0, 0, 0}, NULL },
		{0x31, 0, /* RDTSC */{0, 0, 0}, NULL },
		{0x32, 0, /* RDMSR */{0, 0, 0}, NULL },
		{0x33, 0, /* RDPMC */{0, 0, 0}, NULL },
		{0x34, 0, /* SYSENTER */{0, 0, 0}, NULL },
		{0x35, 0, /* SYSEXIT */{0, 0, 0}, NULL },
		{0x36, 0, /* RDSHR */{0, 0, 0}, NULL },
		{0x37, 0, /* WRSHR */{0, 0, 0}, NULL },
		{0x38, 0, /* SMINT */{0, 0, 0}, NULL },
		{0x39, INS_INVALID, {0, 0, 0}, NULL },
		{0x3a, INS_INVALID, {0, 0, 0}, NULL },
		{0x3b, INS_INVALID, {0, 0, 0}, NULL },
		{0x3c, INS_INVALID, {0, 0, 0}, NULL },
		{0x3d, INS_INVALID, {0, 0, 0}, NULL },
		{0x3e, INS_INVALID, {0, 0, 0}, NULL },
		{0x3f, 0, /* ALTINST */{0, 0, 0}, NULL },
		{0x40, 0, /* CMOVO */{G v, E v, 0}, NULL },
		{0x41, 0, /* CMOVNO */{G v, E v, 0}, NULL },
		{0x42, 0, /* CMOVB */{G v, E v, 0}, NULL },
		{0x43, 0, /* CMOVNB */{G v, E v, 0}, NULL },
		{0x44, 0, /* CMOVZ */{G v, E v, 0}, NULL },
		{0x45, 0, /* CMOVNZ */{G v, E v, 0}, NULL },
		{0x46, 0, /* CMOVBE */{G v, E v, 0}, NULL },
		{0x47, 0, /* CMOVNBE */{G v, E v, 0}, NULL },
		{0x48, 0, /* CMOVS */{G v, E v, 0}, NULL },
		{0x49, 0, /* CMOVNS */{G v, E v, 0}, NULL },
		{0x4a, 0, /* CMOVP */{G v, E v, 0}, NULL },
		{0x4b, 0, /* CMOVNP */{G v, E v, 0}, NULL },
		{0x4c, 0, /* CMOVL */{G v, E v, 0}, NULL },
		{0x4d, 0, /* CMOVNL */{G v, E v, 0}, NULL },
		{0x4e, 0, /* CMOVLE */{G v, E v, 0}, NULL },
		{0x4f, 0, /* CMOVNLE */{G v, E v, 0}, NULL },
		{0x50, 0, /* MOVMSKPS MOVMSKPD */{G d, V ps, 0}, NULL },
		{0x51, 0, /* SQRTPS SQRTSS SQRTPD SQRTSD */{V, W, 0}, NULL },
		{0x52, 0, /* RSQRTPS RSQRTSS */{V, W, 0}, NULL },
		{0x53, 0, /* RCPPS RCPSS */{V, W, 0}, NULL },
		{0x54, 0, /* ANDPS ANDPD */{V ps,W ps, 0}, NULL },
		{0x55, 0, /* ANDNPS ANDNPD */{V ps, W ps, 0}, NULL },
		{0x56, 0, /* ORPS ORPD */{V ps, W ps, 0}, NULL },
		{0x57, 0, /* XORPS XORPD */{V ps, W ps, 0}, NULL },
		{0x58, 0, /* ADDPS ADDSS ADDPD ADDSD */{V, W, 0}, NULL },
		{0x59, 0, /* MULPS MULSS MULPD MULSD */{V, W, 0}, NULL },
		{0x5a, 0, /* CVTPS2PD CVTSS2SD CVTPD2PS CVTSD2SS */{V, W, 0}, NULL },
		{0x5b, 0, /* CVTDQ2PS CVTTPS2DQ CVTPS2DQ */{V ps, W ps, 0}, NULL },
		{0x5c, 0, /* SUBPS SUBSS SUBPD SUBSD */{V, W, 0}, NULL },
		{0x5d, 0, /* MINPS MINSS MINPD MINSD */{V, W, 0}, NULL },
		{0x5e, 0, /* DIVPS DIVSS DIVPD DIVSD */{V, W, 0}, NULL },
		{0x5f, 0, /* MAXPS MAXSS MAXPD MAXSD */{V, W, 0}, NULL },
		{0x60, 0, /* PUNPCKLBW MMX/SSE2 */{V dq, W q, 0}, NULL },
		{0x61, 0, /* PUNPCKLWD MMX/SSE2 */{V dq, W q, 0}, NULL },
		{0x62, 0, /* PUNPCKLDQ MMX/SSE2 */{V dq, W q, 0}, NULL },
		{0x63, 0, /* PACKSSWB MMX/SSE2 */{V dq,W dq, 0}, NULL },
		{0x64, 0, /* PCMPGTB MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0x65, 0, /* PCMPGTW MMX/SSE2 */{V dq,W dq, 0}, NULL },
		{0x66, 0, /* PCMPGTD MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0x67, 0, /* PACKUSWB MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0x68, 0, /* PUNPCKHBW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0x69, 0, /* PUNPCKHWD MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0x6a, 0, /* PUNPCKHDQ MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0x6b, 0, /* PACKSSDW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0x6c, 0, /* PUNPCKLQDQ SSE2 */{V dq, W q, 0}, NULL },
		{0x6d, 0, /* PUNPCKHQDQ SSE2 */{V dq, W dq, 0}, NULL },
		{0x6e, 0, /* MOVD MMX/SSE2 */{V dq, E d, 0}, NULL },
		{0x6f, 0, /* MOVQ MOVDQU MOVDQA MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0x70, 0, /* PSHUFW PSHUFHW PSHUFD PSHUFLW */{V ps, W ps, I b}, NULL },
		{0x71, INS_GROUP, /* group #13 PSHIMW MMX/SSE2 */{V ps, I b, 0}, NULL },
		{0x72, INS_GROUP, /* group #14 PSHIMD MMX/SSE2 */{V ps, I b, 0}, NULL },
		{0x73, INS_GROUP, /* group #15 PSHIMQ MMX/SSE2 */{V ps, I b, 0}, NULL },
		{0x74, 0, /* PCMPEQB */{V ps, W ps, 0}, NULL },
		{0x75, 0, /* PCMPEQW */{V ps, W ps, 0}, NULL },
		{0x76, 0, /* PCMPEQD */{V ps, W ps, 0}, NULL },
		{0x77, 0, /* EMMS */{0, 0, 0}, NULL },
		{0x78, INS_INVALID, {0, 0, 0}, NULL },
		{0x79, INS_INVALID, {0, 0, 0}, NULL },
		{0x7a, INS_INVALID, {0, 0, 0}, NULL },
		{0x7b, INS_INVALID, {0, 0, 0}, NULL },
		{0x7c, 0, /* HADDPD HADDPS */{V ps, W ps, 0}, NULL },
		{0x7d, 0, /* HSUBPD HSUBPS */{V ps, W ps, 0}, NULL },
		{0x7e, 0, /* MOVD MOVQ MOVD MMX/SSE2 */{E, V, 0}, NULL },
		{0x7f, 0, /* MOVQ MOVDQU MOVDQA MMX/SSE2 */{W ps, V ps, 0}, NULL },
		{0x80, 0, /* JO */{J v, 0, 0}, NULL },
		{0x81, 0, /* JNO */{J v, 0, 0}, NULL },
		{0x82, 0, /* JB */{J v, 0, 0}, NULL },
		{0x83, 0, /* JNB */{J v, 0, 0}, NULL },
		{0x84, 0, /* JZ */{J v, 0, 0}, NULL },
		{0x85, 0, /* JNZ */{J v, 0, 0}, NULL },
		{0x86, 0, /* JBE */{J v, 0, 0}, NULL },
		{0x87, 0, /* JNBE */{J v, 0, 0}, NULL },
		{0x88, 0, /* JS */{J v, 0, 0}, NULL },
		{0x89, 0, /* JNS */{J v, 0, 0}, NULL },
		{0x8a, 0, /* JP */{J v, 0, 0}, NULL },
		{0x8b, 0, /* JNP */{J v, 0, 0}, NULL },
		{0x8c, 0, /* JL */{J v, 0, 0}, NULL },
		{0x8d, 0, /* JNL */{J v, 0, 0}, NULL },
		{0x8e, 0, /* JLE */{J v, 0, 0}, NULL },
		{0x8f, 0, /* JNLE */{J v, 0, 0}, NULL },
		{0x90, 0, /* SETO */{E b, 0, 0}, NULL },
		{0x91, 0, /* SETNO */{E b, 0, 0}, NULL },
		{0x92, 0, /* SETB */{E b, 0, 0}, NULL },
		{0x93, 0, /* SETNB */{E b, 0, 0}, NULL },
		{0x94, 0, /* SETZ */{E b, 0, 0}, NULL },
		{0x95, 0, /* SETNZ */{E b, 0, 0}, NULL },
		{0x96, 0, /* SETBE */{E b, 0, 0}, NULL },
		{0x97, 0, /* SETNBE */{E b, 0, 0}, NULL },
		{0x98, 0, /* SETS */{E b, 0, 0}, NULL },
		{0x99, 0, /* SETNS */{E b, 0, 0}, NULL },
		{0x9a, 0, /* SETP */{E b, 0, 0}, NULL },
		{0x9b, 0, /* SETNP */{E b, 0, 0}, NULL },
		{0x9c, 0, /* SETL */{E b, 0, 0}, NULL },
		{0x9d, 0, /* SETNL */{E b, 0, 0}, NULL },
		{0x9e, 0, /* SETLE */{E b, 0, 0}, NULL },
		{0x9f, 0, /* SETNLE */{E b, 0, 0}, NULL },
		{0xa0, 0, /* PUSH FS */{0, 0, 0}, NULL },
		{0xa1, 0, /* POP FS */{0, 0, 0}, NULL },
		{0xa2, 0, /* CPUID */{0, 0, 0}, NULL },
		{0xa3, 0, /* BT */{E v, G v, 0}, NULL },
		{0xa4, 0, /* SHLD */{E v, G v, I b}, NULL },
		{0xa5, 0, /* SHLD x,x,CL */{E v, G v, 0}, NULL },
		{0xa6, 0, /* XBTS and CMPXCHG */{0, 0, 0}, NULL },
		{0xa7, 0, /* IBTS and CMPXCHG XSTORE XCRYPT */{0, 0, 0}, NULL },
		{0xa8, 0, /* PUSH GS */{0, 0, 0}, NULL },
		{0xa9, 0, /* POP GS */{0, 0, 0}, NULL },
		{0xaa, 0, /* RSM (SMM) */{0, 0, 0}, NULL },
		{0xab, 0, /* BTS */{E v, G v, 0}, NULL },
		{0xac, 0, /* SHRD */{E v, G v, I b}, NULL },
		{0xad, 0, /* SHRD x,x,CL */{E v, G v, 0}, NULL },
		{0xae, INS_GROUP, /* group #16 */{0, 0, 0}, Gr16OpCode },
		{0xaf, 0, /* IMUL */{G v, E v, 0}, NULL },
		{0xb0, 0, /* CMPXCHG */{E b, G b, 0}, NULL },
		{0xb1, 0, /* CMPXCHG */{E v, G v, 0}, NULL },
		{0xb2, 0, /* LSS */{G v, M p, 0}, NULL },
		{0xb3, 0, /* BTR */{E v, G v, 0}, NULL },
		{0xb4, 0, /* LFS */{G v, M p, 0}, NULL },
		{0xb5, 0, /* LGS */{G v, M p, 0}, NULL },
		{0xb6, 0, /* MOVZX */{G v, E b, 0}, NULL },
		{0xb7, 0, /* MOVZX */{G v, E w, 0}, NULL },
		{0xb8, 0, /* JMPE */{J v, 0, 0}, NULL },
		{0xb9, INS_GROUP, /* group #11 UD2 */{0, 0, 0}, NULL },
		{0xba, INS_GROUP, /* group #8 */{E v, I b, 0}, NULL },
		{0xbb, 0, /* BTC */{E v, G v, 0}, NULL },
		{0xbc, 0, /* BSF */{G v, E v, 0}, NULL },
		{0xbd, 0, /* BSR */{G v, E v, 0}, NULL },
		{0xbe, 0, /* MOVSX */{G v, E b, 0}, NULL },
		{0xbf, 0, /* MOVSX */{G v, E w, 0}, NULL },
		{0xc0, 0, /* XADD */{E b, G b, 0}, NULL },
		{0xc1, 0, /* XADD */{E v, G v, 0}, NULL },
		{0xc2, 0, /* CMPccPS CMPccSS CMPccPD CMPccSD */{V, W, I}, NULL },
		{0xc3, 0, /* MOVNTI */{M d, G d, 0}, NULL },
		{0xc4, 0, /* PINSRW */{V ps, M w, I b}, NULL },
		{0xc5, 0, /* PEXTRW */{G d, V ps, I b}, NULL }, 
		{0xc6, 0, /* SHUFPS */{V ps, W ps, I b}, NULL },
		{0xc7, INS_GROUP, /* group #9 CMPXCHG */{M q, 0, 0}, NULL },
		{0xc8, 0, /* BSWAP EAX */{0, 0, 0}, NULL },
		{0xc9, 0, /* BSWAP ECX */{0, 0, 0}, NULL },
		{0xca, 0, /* BSWAP EDX */{0, 0, 0}, NULL },
		{0xcb, 0, /* BSWAP EBX */{0, 0, 0}, NULL },
		{0xcc, 0, /* BSWAP ESP */{0, 0, 0}, NULL },
		{0xcd, 0, /* BSWAP EBP */{0, 0, 0}, NULL },
		{0xce, 0, /* BSWAP ESI */{0, 0, 0}, NULL },
		{0xcf, 0, /* BSWAP EDI */{0, 0, 0}, NULL },
		{0xd0, 0, /* ADDSUBPD ADDSUBdq PAVGB */{V dq, W dq, 0}, NULL },
		{0xd1, 0, /* dqRLW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xd2, 0, /* dqRLD MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xd3, 0, /* dqRLQ MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xd4, 0, /* PADDQ MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xd5, 0, /* PMULLW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xd6, 0, /* MOVQ2DQ MOVQ MOVDQ2Q */{W, V, 0}, NULL },
		{0xd7, 0, /* PMOVMSKB */{G d, V dq, 0}, NULL },
		{0xd8, 0, /* dqUBUSB MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xd9, 0, /* dqUBUSW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xda, 0, /* PMINUB MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xdb, 0, /* PAND MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xdc, 0, /* PADDUSB MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xdd, 0, /* PADDUSW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xde, 0, /* PMAXUB MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xdf, 0, /* PANDN MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xe0, 0, /* PAVGB MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xe1, 0, /* dqRAW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xe2, 0, /* dqRAD MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xe3, 0, /* PAVGW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xe4, 0, /* PMULHUW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xe5, 0, /* PMULHW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xe6, 0, /* CVTDQ2PD CVTTPD2DQ MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xe7, 0, /* MOVNTQ MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xe8, 0, /* dqUBSB MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xe9, 0, /* dqUBSW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xea, 0, /* PMINSW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xeb, 0, /* POR MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xec, 0, /* PADDSB MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xed, 0, /* PADDSW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xee, 0, /* PMAXSW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xef, 0, /* PXOR MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xf0, 0, /* LDDQU */{V dq, M dq, 0}, NULL },
		{0xf1, 0, /* dqLLW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xf2, 0, /* dqLLD MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xf3, 0, /* dqLLQ MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xf4, 0, /* PMULUDQ MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xf5, 0, /* PMADDWD MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xf6, 0, /* dqADBW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xf7, 0, /* MASKMOVQ MASKMOVDQU MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xf8, 0, /* PSUBB MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xf9, 0, /* PSUBW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xfa, 0, /* PSUBD MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xfb, 0, /* PSUBQ MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xfc, 0, /* PADDB MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xfd, 0, /* PADDW MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xfe, 0, /* PADDD MMX/SSE2 */{V dq, W dq, 0}, NULL },
		{0xff, 0, /* UD (AMD) */{V dq, W dq, 0}, NULL }
	};

	InstructionInfo Gr3OpCode[] = {
		{0x0, 0, /* TEST */{0, I, 0}, NULL },
		{0x1, 0, /* TEST */{0, I, 0}, NULL },
		{0x2, 0, /* NOT */{0, 0, 0}, NULL },
		{0x3, 0, /* NEG */{0, 0, 0}, NULL },
		{0x4, 0, /* MUL AL/eAX */{0, 0, 0}, NULL },
		{0x5, 0, /* IMUL AL/eAX */{0, 0, 0}, NULL },
		{0x6, 0, /* DIV AL/eAX */{0, 0, 0}, NULL },
		{0x7, 0, /* IDIV AL/eAX */{0, 0, 0}, NULL }
	};

	InstructionInfo ObOpcode[] = {
		{0x00, 0, /* ADD */{E b, G b, 0}, NULL },
		{0x01, 0, /* ADD */{E v, G v, 0}, NULL },
		{0x02, 0, /* ADD */{G b, E b, 0}, NULL },
		{0x03, 0, /* ADD */{G v, E v, 0}, NULL },
		{0x04, 0, /* ADD AL */{0, I b, 0}, NULL },
		{0x05, 0, /* ADD eAX */{0, I v, 0}, NULL },
		{0x06, 0, /* PUSH ES */{0, 0, 0}, NULL },
		{0x07, 0, /* POP ES */{0, 0, 0}, NULL },
		{0x08, 0, /* OR */{E b, G b, 0}, NULL }, 
		{0x09, 0, /* OR */{E v, G v, 0}, NULL },
		{0x0a, 0, /* OR */{G b, E b, 0}, NULL },
		{0x0b, 0, /* OR */{G v, E v, 0}, NULL },
		{0x0c, 0, /* OR AL */{0, I b, 0}, NULL },
		{0x0d, 0, /* OR eAX */{I v, 0, 0}, NULL },
		{0x0e, 0, /* PUSH CS */{0, 0, 0}, NULL },
		{0x0f, INS_ESCAPE, /* two byte opcodes*/{0, 0, 0}, TbOpCode },
		{0x10, 0, /* ADC */{E b, G b, 0}, NULL },
		{0x11, 0, /* ADC */{E v, G v, 0}, NULL },
		{0x12, 0, /* ADC */{G b, E b, 0}, NULL },
		{0x13, 0, /* ADC */{G v, E v, 0}, NULL },
		{0x14, 0, /* ADC AL */{I b, 0, 0}, NULL },
		{0x15, 0, /* ADC eAX */{I v, 0, 0}, NULL },
		{0x16, 0, /* PUSH SS */{0, 0, 0}, NULL },
		{0x17, 0, /* POP SS */{0, 0, 0}, NULL },
		{0x18, 0, /* SBB */{E b, G b, 0}, NULL },
		{0x19, 0, /* SBB */{E v, G v, 0}, NULL },
		{0x1a, 0, /* SBB */{G b, E b, 0}, NULL },
		{0x1b, 0, /* SBB */{G v, E v, 0}, NULL },
		{0x1c, 0, /* SBB AL */{I b, 0, 0}, NULL },
		{0x1d, 0, /* SBB eAX */{I v, 0, 0}, NULL },
		{0x1e, 0, /* PUSH DS */{0, 0, 0}, NULL },
		{0x1f, 0, /* POP DS */{0, 0, 0}, NULL },
		{0x20, 0, /* AND */{E b, G b, 0}, NULL },
		{0x21, 0, /* AND */{E v, G v, 0}, NULL },
		{0x22, 0, /* AND */{G b, E b, 0}, NULL },
		{0x23, 0, /* AND */{G v, E v, 0}, NULL },
		{0x24, 0, /* AND AL */{I b, 0, 0}, NULL },
		{0x25, 0, /* AND eAx */{I v, 0, 0}, NULL },
		{0x26, INS_PREFIX, /* ES: */{0, 0, 0}, NULL },
		{0x27, 0, /* DAA */{0, 0, 0}, NULL },
		{0x28, 0, /* SUB */{E b, G b, 0}, NULL },
		{0x29, 0, /* SUB */{E v, G v, 0}, NULL },
		{0x2a, 0, /* SUB */{G b, E b, 0}, NULL },
		{0x2b, 0, /* SUB */{G v, E v, 0}, NULL },
		{0x2c, 0, /* SUB AL */{I b, 0, 0}, NULL },
		{0x2d, 0, /* SUB eAX */{I v, 0, 0}, NULL },
		{0x2e, INS_PREFIX, /* CS: */{0, 0, 0}, NULL },
		{0x2f, 0, /* DAS */{0, 0, 0}, NULL },
		{0x30, 0, /* XOR */{E b, G b, 0}, NULL },
		{0x31, 0, /* XOR */{E v, G v, 0}, NULL },
		{0x32, 0, /* XOR */{G b, E b, 0}, NULL },
		{0x33, 0, /* XOR */{G v, E v, 0}, NULL },
		{0x34, 0, /* XOR AL */{I b, 0, 0}, NULL },
		{0x35, 0, /* XOR eAX */{I v, 0, 0}, NULL },
		{0x36, INS_PREFIX, /* SS: */{0, 0, 0}, NULL },
		{0x37, 0, /* AAA */{0, 0, 0}, NULL },
		{0x38, 0, /* CMP */{E b, G b, 0}, NULL },
		{0x39, 0, /* CMP */{E v, G v, 0}, NULL },
		{0x3a, 0, /* CMP */{G b, E b, 0}, NULL },
		{0x3b, 0, /* CMP */{G v, E v, 0}, NULL },
		{0x3c, 0, /* CMP AL */{I b, 0, 0}, NULL },
		{0x3d, 0, /* CMP eAX */{I v, 0, 0}, NULL },
		{0x3e, INS_PREFIX, /* DS: */{0, 0, 0}, NULL },
		{0x3f, 0, /* AAS */{0, 0, 0}, NULL },
		{0x40, INS_REX_PREFIX, /* INC eAX */{0, 0, 0}, NULL },
		{0x41, INS_REX_PREFIX, /* INC eCX */{0, 0, 0}, NULL },
		{0x42, INS_REX_PREFIX, /* INC eDX */{0, 0, 0}, NULL },
		{0x43, INS_REX_PREFIX, /* INC eBX */{0, 0, 0}, NULL },
		{0x44, INS_REX_PREFIX, /* INC eSP */{0, 0, 0}, NULL },
		{0x45, INS_REX_PREFIX, /* INC eBP */{0, 0, 0}, NULL },
		{0x46, INS_REX_PREFIX, /* INC eSI */{0, 0, 0}, NULL },
		{0x47, INS_REX_PREFIX, /* INC eDI */{0, 0, 0}, NULL },
		{0x48, INS_REX_PREFIX | INS_REX_W, /* DEC eAX */{0, 0, 0}, NULL },
		{0x49, INS_REX_PREFIX, /* DEC eCX */{0, 0, 0}, NULL },
		{0x4a, INS_REX_PREFIX, /* DEC eDX */{0, 0, 0}, NULL },
		{0x4b, INS_REX_PREFIX, /* DEC eBX */{0, 0, 0}, NULL },
		{0x4c, INS_REX_PREFIX, /* DEC eSP */{0, 0, 0}, NULL },
		{0x4d, INS_REX_PREFIX, /* DEC eBP */{0, 0, 0}, NULL },
		{0x4e, INS_REX_PREFIX, /* DEC eSI */{0, 0, 0}, NULL },
		{0x4f, INS_REX_PREFIX, /* DEC eDI */{0, 0, 0}, NULL },
		{0x50, 0, /* PUSH eAX */{0, 0, 0}, NULL },
		{0x51, 0, /* PUSH eCX */{0, 0, 0}, NULL },
		{0x52, 0, /* PUSH eDX */{0, 0, 0}, NULL },
		{0x53, 0, /* PUSH eBX */{0, 0, 0}, NULL },
		{0x54, 0, /* PUSH eSP */{0, 0, 0}, NULL },
		{0x55, 0, /* PUSH eBP */{0, 0, 0}, NULL },
		{0x56, 0, /* PUSH eSI */{0, 0, 0}, NULL },
		{0x57, 0, /* PUSH eDI */{0, 0, 0}, NULL },
		{0x58, 0, /* POP eAX */{0, 0, 0}, NULL },
		{0x59, 0, /* POP eCX */{0, 0, 0}, NULL },
		{0x5a, 0, /* POP eDX */{0, 0, 0}, NULL },
		{0x5b, 0, /* POP eBX */{0, 0, 0}, NULL },
		{0x5c, 0, /* POP eSP */{0, 0, 0}, NULL },
		{0x5d, 0, /* POP eBP */{0, 0, 0}, NULL },
		{0x5e, 0, /* POP eSI */{0, 0, 0}, NULL },
		{0x5f, 0, /* POP eDI */{0, 0, 0}, NULL },
		{0x60, 0, /* PUSHA/PUSHAD */{0, 0, 0}, NULL },
		{0x61, 0, /* POPA/POPAD */{0, 0, 0}, NULL },
		{0x62, 0, /* BOUND */{G v, M a, 0}, NULL },
		{0x63, 0, /* ARPL MOVSXD */{E w, R w, 0}, NULL },
		{0x64, INS_PREFIX, /* FS: */{0, 0, 0}, NULL },
		{0x65, INS_PREFIX, /* GS: */{0, 0, 0}, NULL },
		{0x66, INS_PREFIX | INS_OPSIZE_PREFIX, /* OPSIZE: */{0, 0, 0}, NULL },
		{0x67, INS_PREFIX | INS_ADSIZE_PREFIX, /* ADSIZE: */{0, 0, 0}, NULL },
		{0x68, 0, /* PUSH */{I v, 0, 0}, NULL }, // andr: check for 64 value!!!
		{0x69, 0, /* IMUL */{G v, E v, I v}, NULL },
		{0x6a, 0, /* PUSH */{I b, 0, 0}, NULL },
		{0x6b, 0, /* IMUL */{G v, E v, I b}, NULL },
		{0x6c, 0, /* INSB x, DX*/{Y b, 0, 0}, NULL },
		{0x6d, 0, /* INSW/D x, DX*/{Y v, 0, 0}, NULL },
		{0x6e, 0, /* OUTSB DX*/{X b, 0, 0}, NULL },
		{0x6f, 0, /* OUTSW/D DX*/{X v, 0, 0}, NULL },
		{0x70, 0, /* JO */{J b, 0, 0}, NULL },
		{0x71, 0, /* JNO */{J b, 0, 0}, NULL },
		{0x72, 0, /* JB */{J b, 0, 0}, NULL },
		{0x73, 0, /* JNB */{J b, 0, 0}, NULL },
		{0x74, 0, /* JZ */{J b, 0, 0}, NULL },
		{0x75, 0, /* JNZ */{J b, 0, 0}, NULL },
		{0x76, 0, /* JBE */{J b, 0, 0}, NULL },
		{0x77, 0, /* JNBE */{J b, 0, 0}, NULL },
		{0x78, 0, /* JS */{J b, 0, 0}, NULL },
		{0x79, 0, /* JNS */{J b, 0, 0}, NULL },
		{0x7a, 0, /* JP */{J b, 0, 0}, NULL },
		{0x7b, 0, /* JNP */{J b, 0, 0}, NULL },
		{0x7c, 0, /* JL */{J b, 0, 0}, NULL },
		{0x7d, 0, /* JNL */{J b, 0, 0}, NULL },
		{0x7e, 0, /* JLE */{J b, 0, 0}, NULL },
		{0x7f, 0, /* JNLE */{J b, 0, 0}, NULL },
		{0x80, INS_GROUP, /* group #1 */{E b, I b, 0}, NULL },
		{0x81, INS_GROUP, /* group #1 */{E v, I v, 0}, NULL },
		{0x82, INS_GROUP, /* group #1 */{E b, I b, 0}, NULL },
		{0x83, INS_GROUP, /* group #1 */{E v, I b, 0}, NULL },
		{0x84, 0, /* TEST */{E b, G b, 0}, NULL },
		{0x85, 0, /* TEST */{E v, G v, 0}, NULL },
		{0x86, 0, /* XCHG */{E b, G b, 0}, NULL },
		{0x87, 0, /* XCHG */{E v, G v, 0}, NULL }, 
		{0x88, 0, /* MOV */{E b, G b, 0}, NULL },
		{0x89, 0, /* MOV */{E v, G v, 0}, NULL },
		{0x8a, 0, /* MOV */{G b, E b, 0}, NULL },
		{0x8b, 0, /* MOV */{G v, E v, 0}, NULL },
		{0x8c, 0, /* MOV */{E w, S w, 0}, NULL },
		{0x8d, 0, /* LEA */{G v, M, 0}, NULL },
		{0x8e, 0, /* MOV */{S w, E w, 0}, NULL },
		{0x8f, INS_GROUP, /* group #10 */{E v, 0, 0}, NULL },
		{0x90, 0, /* NOP */{0, 0, 0}, NULL },
		{0x91, 0, /* XCHG eCX,eAX */{0, 0, 0}, NULL },
		{0x92, 0, /* XCHG eDX,eAX */{0, 0, 0}, NULL },
		{0x93, 0, /* XCHG eBX,eAX */{0, 0, 0}, NULL },
		{0x94, 0, /* XCHG eSP,eAX */{0, 0, 0}, NULL },
		{0x95, 0, /* XCHG eBP,eAX */{0, 0, 0}, NULL },
		{0x96, 0, /* XCHG eSI,eAX */{0, 0, 0}, NULL },
		{0x97, 0, /* XCHG eDI,eAX */{0, 0, 0}, NULL },
		{0x98, 0, /* CBW/CWDE */{0, 0, 0}, NULL },
		{0x99, 0, /* CWD/CDQ */{0, 0, 0}, NULL },
		{0x9a, 0, /* CALL */{A p, 0, 0}, NULL },
		{0x9b, 0, /* WAIT FWAIT */{0, 0, 0}, NULL },
		{0x9c, 0, /* PUSHF */{F v, 0, 0}, NULL },
		{0x9d, 0, /* POPF */{F v, 0, 0}, NULL },
		{0x9e, 0, /* SAHF */{0, 0, 0}, NULL },
		{0x9e, 0, /* LAHF */{0, 0, 0}, NULL },
		{0xa0, INS_64VALUE, /* MOV AL */{0, O b, 0}, NULL },
		{0xa1, INS_64VALUE, /* MOV eAX */{0, O v, 0}, NULL },
		{0xa2, INS_64VALUE, /* MOV x, AL */{O b, 0, 0}, NULL },
		{0xa3, INS_64VALUE, /* MOV x, eAX */{O v, 0, 0}, NULL },
		{0xa4, 0, /* MOVSB */{Y b, X b, 0}, NULL },
		{0xa5, 0, /* MOVSW/D */{Y v, X v, 0}, NULL },
		{0xa6, 0, /* CMPSB */{Y b, X b, 0}, NULL },
		{0xa7, 0, /* CMPSW/D */{Y v, X v, 0}, NULL },
		{0xa8, 0, /* TEST AL */{0, I b, 0}, NULL },
		{0xa9, 0, /* TEST eAX */{0, I v, 0}, NULL },
		{0xaa, 0, /* STOSB x, AL */{Y b, 0, 0}, NULL },
		{0xab, 0, /* STOSW/D x eAX */{Y v, 0, 0}, NULL },
		{0xac, 0, /* LODSB AL */{0, X b, 0}, NULL },
		{0xad, 0, /* LODSW/D eAX */{0, X v, 0}, NULL },
		{0xae, 0, /* SCASB x, AL */{Y b, 0, 0}, NULL },
		{0xaf, 0, /* SCASW/D x, eAX */{Y v, 0, 0}, NULL },
		{0xb0, 0, /* MOV AL */{0, I b, 0}, NULL },
		{0xb1, 0, /* MOV CL */{0, I b, 0}, NULL },
		{0xb2, 0, /* MOV DL */{0, I b, 0}, NULL },
		{0xb3, 0, /* MOV BL */{0, I b, 0}, NULL },
		{0xb4, 0, /* MOV AH */{0, I b, 0}, NULL },
		{0xb5, 0, /* MOV CH */{0 ,I b, 0}, NULL },
		{0xb6, 0, /* MOV DH */{0, I b, 0}, NULL },
		{0xb7, 0, /* MOV BH */{0, I b, 0}, NULL },
		{0xb8, INS_64VALUE, /* MOV eAX */{0, I v, 0}, NULL },
		{0xb9, INS_64VALUE, /* MOV eCX */{0, I v, 0}, NULL },
		{0xba, INS_64VALUE, /* MOV eDX */{0, I v, 0}, NULL },
		{0xbb, INS_64VALUE, /* MOV eBX */{0, I v, 0}, NULL },
		{0xbc, INS_64VALUE, /* MOV eSP */{0, I v, 0}, NULL },
		{0xbd, INS_64VALUE, /* MOV eBP */{0, I v, 0}, NULL },
		{0xbe, INS_64VALUE, /* MOV eSI */{0, I v, 0}, NULL },
		{0xbf, INS_64VALUE, /* MOV eDI */{0, I v, 0}, NULL },
		{0xc0, INS_GROUP, /* group #2 */{E b, I b, 0}, NULL },
		{0xc1, INS_GROUP, /* group #2 */{E v, I b, 0}, NULL },
		{0xc2, INS_RET, /* RET near */{I w, 0, 0}, NULL },
		{0xc3, INS_RET, /* RET near */{0, 0, 0}, NULL },
		{0xc4, 0, /* LES */{G v, M p, 0}, NULL },
		{0xc5, 0, /* LDS */{G v, M p, 0}, NULL },
		{0xc6, INS_GROUP, /* group #12 */{E b, I b, 0}, NULL },
		{0xc7, INS_GROUP, /* group #12 */{E v, I v, 0}, NULL },
		{0xc8, 0, /* ENTER */{I w, I b, 0}, NULL },
		{0xc9, 0, /* LEAVE */{0, 0, 0}, NULL },
		{0xca, INS_RET, /* RET far */{I w, 0, 0}, NULL },
		{0xcb, INS_RET, /* RET far */{0, 0, 0}, NULL },
		{0xcc, 0, /* INT3 */{0, 0, 0}, NULL },
		{0xcd, 0, /* INT */{I b, 0, 0}, NULL },
		{0xce, 0, /* INTO */{0, 0, 0}, NULL },
		{0xcf, INS_RET, /* IRET */{0, 0, 0}, NULL },
		{0xd0, INS_GROUP, /* group #2 x,1 */{E b, 0, 0}, NULL },
		{0xd1, INS_GROUP, /* group #2 x,1 */{E v, 0, 0}, NULL },
		{0xd2, INS_GROUP, /* group #2 x,CL */{E b, 0, 0}, NULL },
		{0xd3, INS_GROUP, /* group #2 x,CL */{E v, 0, 0}, NULL },
		{0xd4, 0, /* AAM */{I b, 0, 0}, NULL },
		{0xd5, 0, /* AAD */{I b, 0, 0}, NULL },
		{0xd6, 0, /* SALC SETALC */{0, 0, 0}, NULL },
		{0xd7, 0, /* XLAT */{0, 0, 0}, NULL },
		{0xd8, INS_ESCAPE, /* ESC 0 */{M, 0, 0}, NULL },
		{0xd9, INS_ESCAPE, /* ESC 1 */{M, 0, 0}, NULL },
		{0xda, INS_ESCAPE, /* ESC 2 */{M, 0, 0}, NULL },
		{0xdb, INS_ESCAPE, /* ESC 3 */{M, 0, 0}, NULL },
		{0xdc, INS_ESCAPE, /* ESC 4 */{M, 0, 0}, NULL },
		{0xdd, INS_ESCAPE, /* ESC 5 */{M, 0, 0}, NULL },
		{0xde, INS_ESCAPE, /* ESC 6 */{M, 0, 0}, NULL },
		{0xdf, INS_ESCAPE, /* ESC 7 */{M, 0, 0}, NULL },
		{0xe0, 0, /* LOOPNE LOOPNZ */{J b, 0, 0}, NULL },
		{0xe1, 0, /* LOOPE LOOPZ */{J b, 0, 0}, NULL },
		{0xe2, 0, /* LOOP */ {J b, 0, 0}, NULL },
		{0xe3, 0, /* JCXZ JECX */ {J b, 0, 0}, NULL },
		{0xe4, 0, /* IN AL */{0, I b, 0}, NULL },
		{0xe5, 0, /* IN eAX */{0, I b, 0}, NULL },
		{0xe6, 0, /* OUT x,AL */{I b, 0, 0}, NULL },
		{0xe7, 0, /* OUT x,eAX */{I b, 0, 0}, NULL },
		{0xe8, 0, /* CALL */{J v, 0, 0}, NULL },
		{0xe9, 0, /* JMP */{J v, 0, 0}, NULL },
		{0xea, 0, /* JMP */{A p, 0, 0}, NULL },
		{0xeb, 0, /* JMP */{J b, 0, 0}, NULL },
		{0xec, 0, /* IN AL,DX */{0, 0, 0}, NULL },
		{0xed, 0, /* IN eAX,DX */{0, 0, 0}, NULL },
		{0xee, 0, /* OUT DX,AL */{0, 0, 0}, NULL },
		{0xef, 0, /* OUT DX,eAX */{0, 0, 0}, NULL },
		{0xf0, INS_PREFIX,  /* LOCK: */{0, 0, 0}, NULL },
		{0xf1, 0, /* INT1 (ICEBP) */{0, 0, 0}, NULL },
		{0xf2, INS_PREFIX, /* REPNE: */{0, 0, 0}, NULL },
		{0xf3, INS_PREFIX, /* REP: REPE: */{0, 0, 0}, NULL },
		{0xf4, 0, /* HLT */{0, 0, 0}, NULL },
		{0xf5, 0, /* CMC */{0, 0, 0}, NULL },
		{0xf6, INS_GROUP, /* group #3 */{E b, 0 b, 0}, Gr3OpCode },
		{0xf7, INS_GROUP, /* group #3 */{E v, 0 v, 0}, Gr3OpCode },
		{0xf8, 0, /* CLC */{0, 0, 0}, NULL },
		{0xf9, 0, /* STC */{0, 0, 0}, NULL },
		{0xfa, 0, /* CLI */{0, 0, 0}, NULL },
		{0xfb, 0, /* STI */{0, 0, 0}, NULL },
		{0xfc, 0, /* CLD */{0, 0, 0}, NULL },
		{0xfd, 0, /* STD */{0, 0, 0}, NULL },
		{0xfe, INS_GROUP, /* group #4 INC/DEC */{E b, 0, 0}, NULL },
		{0xff, INS_GROUP, /* group #5 INC/DEC */{E v, 0, 0}, NULL }
	};

#define PARSE_MODRM			(0x10000)

	struct ParseState {
		ULONG Flags;
		ULONG ParseFlags;
		CodeWidth Width;
		ULONG Params[3];
		ULONG JOffset;
		ULONG JLength;
		PBYTE Next;
		ULONG Length;
	};

	ParseState State = { 0, 0, cwt32, NULL, 0 };

#define MODRM_SIB			(1)

	struct ModRMInfo {
		ULONG Size;
		ULONG Flags;
	};
	
	ModRMInfo ModRM[4][8][2] = { 
		  { 
			{ {0, 0}, {0, 0} }, { {0, 0}, {0, 0} }, { {0, 0}, {0, 0} }, { {0, 0}, {0, 0} },
		    { {0, 0}, {0, MODRM_SIB} }, { {0, 0}, {4, 0} }, { {0, 0}, {0, 0} }, { {0, 0}, {0, 0} }
		  },
		  { 
			{ {1, 0}, {1, 0} }, { {1, 0}, {1, 0} }, { {1, 0}, {1, 0} }, { {1, 0}, {1, 0} },
		    { {1, 0}, {0, MODRM_SIB} }, { {1, 0}, {1, 0} }, { {1, 0}, {1, 0} }, { {1, 0}, {1, 0} }
		  },
		  { 
			{ {2, 0}, {4, 0} }, { {2, 0}, {4, 0} }, { {2, 0}, {4, 0} }, { {2, 0}, {4, 0} },
		    { {2, 0}, {0, MODRM_SIB} }, { {2, 0}, {4, 0} }, { {2, 0}, {4, 0} }, { {2, 0}, {4, 0} }
		  },
		  { 
			{ {0, 0}, {0, 0} }, { {0, 0}, {0, 0} }, { {0, 0}, {0, 0} }, { {0, 0}, {0, 0} },
		    { {0, 0}, {0, 0} }, { {0, 0}, {0, 0} }, { {0, 0}, {0, 0} }, { {0, 0}, {0, 0} }
		  }
	};

	ULONG ParseModRM(PBYTE modrm);
	ULONG GetOperandSize(ULONG SizeFlag);
};

ULONG x86::Parse(PBYTE Code)
{
	InstructionInfo *Info = &ObOpcode[*Code];
	State.ParseFlags = 0;
	State.JOffset = 0;
	State.JLength = 0;
	State.Length = 1;

	if ( Info->Flags & INS_INVALID ) return 0;

	while ( Info->Flags & INS_PREFIX || ( State.Width == cwt64 && Info->Flags & INS_REX_PREFIX ) ) {
		State.ParseFlags |= Info->Flags;
		Info = &ObOpcode[*++Code];
		State.Length++;
	}

	while ( Info->Escape != NULL && ( Info->Flags & INS_ESCAPE ) ) {
		Info = &Info->Escape[*++Code];
		State.Length++;
	}

	memcpy(State.Params, Info->Params, sizeof State.Params);

	if ( Info->Escape != NULL  && ( Info->Flags & INS_GROUP ) ) {
		ULONG Index = ( *(Code+1) & 0x38 ) >> 3;
		Info = &Info->Escape[Index];
		for ( ULONG i = 0; i < sizeof State.Params / sizeof State.Params[0]; i++ ) 
			State.Params[i] |= Info->Params[i];

		if ( State.Params[0] == 0 && State.Params[1] == 0 && State.Params[2] == 0 )
			State.Params[0] = SH;
	}

	State.Flags = Info->Flags;

	ULONG Length = 0;
	for ( ULONG i = 0; i < sizeof State.Params / sizeof State.Params[0]; i++ ) {
		switch ( State.Params[i] & 0xffffff00 ) {
			case A:
				Length += 6;
				break;

			case C:
			case D:
			case E:
			case G:
			case M:
			case P:
			case PR:
			case Q:
			case R:
			case S:
			case V:
			case VR:
			case W:
			case T:
				Length += ParseModRM(Code+1);
				break;

			case F:
			case X:
			case Y:
				// Length += 0;
				break;

			case I:
				Length += GetOperandSize(State.Params[i] & 0xff);
				break;

			case J:
				Length += GetOperandSize(State.Params[i] & 0xff);
				State.JOffset = State.Length;
				State.JLength = Length;
				break;

			case O:
				{
					CodeWidth Width = State.Width;
					if ( State.ParseFlags & INS_ADSIZE_PREFIX && State.Width != cwt64 )
						Width = Width == cwt32 ? cwt16 : cwt32;

					if ( State.Width == cwt16 )
						Length += 2;
					else
					if ( State.Width == cwt32 )
						Length += 4;
					else
/* andr: ???
					if ( State.Width == cwt64 && State.ParseFlags & ( INS_64VALUE & INS_REX_W ) )
						Length += 8;
					else
*/
					if ( State.Width == cwt64 )
						Length += 4;
				}
				break;

			case SH:
				Length += 1;
				break;
		}
	}

	State.Length += Length;
	Code += Length;
	State.Next = Code;

	return State.Length;
}

ULONG x86::ParseModRM(PBYTE modrm)
{
	if ( State.ParseFlags & PARSE_MODRM ) return 0;

	ULONG Length = 1;

	CodeWidth Width = State.Width;
	if ( Width > cwt32 ) Width = cwt32;
	if ( State.ParseFlags & INS_ADSIZE_PREFIX && State.Width != cwt64 )
		Width = Width == cwt32 ? cwt16 : cwt32;

	BYTE mod = *modrm >> 6;
	ModRMInfo *Info = &ModRM[mod][*modrm & 0x07][Width-1];
	Length += Info->Size;

	if ( Info->Flags & MODRM_SIB ) {
		PBYTE Sib = modrm + 1;
		Length++;
		if ( (*Sib & 0x07) == 0x05 ) {
			if ( mod == 0x01 ) 
				Length += 1;
			else
				Length += 4;
		} else {
			if ( mod == 0x01 )
				Length += 1;
			else
			if ( mod == 0x02 )
				Length += 4;
		}
	};

	State.ParseFlags |= PARSE_MODRM;

	return Length;
}

ULONG x86::GetOperandSize(ULONG SizeFlag)
{
	CodeWidth Width = State.Width;

	if ( Width == cwt64 && State.ParseFlags & ( INS_64VALUE & INS_REX_W ) )
		return 8;

	if ( Width > cwt32 ) Width = cwt32;
	if ( State.ParseFlags & INS_OPSIZE_PREFIX )
		Width = Width == cwt32 ? cwt16 : cwt32;

	ULONG Length = Width == cwt16 ? 2 : 4;

	switch ( SizeFlag ) {
		case 0 a:
			break;

		case 0 b:
			Length = 1;
			break;

		case 0 d:
			Length = 4;
			break;

		case 0 dq:
			Length = 16;
			break;

		case 0 p:
			Length = Length == 2 ? 4 : 6;
			break;

		case 0 pd:
			Length = 16;
			break;

		case 0 pi:
			Length = 8;
			break;

		case 0 ps:
			Length = 16;
			break;

		case 0 q:
			Length = 8;
			break;

		case 0 s:
			Length = Length == 2 ? 6 : 10;
			break;

		case 0 sd:
			Length = 4;
			break;

		case 0 si:
			Length = 4;
			break;

		case 0 ss:
			Length = 4; // andr: ?????
			break;

		case 0 v:
			break;

		case 0 w:
			Length = 2;
			break;

		case 0 z:
			break;

		case 0 sn:
			break;
	}

	return Length;
}

VOID x86::InitParse(CodeWidth Width)
{ 
	State.Flags = 0; 
	State.ParseFlags = 0;
	State.Width = Width;
	State.Next = NULL; 
	State.Length = 0; 
}

#if !defined(_AMD64_) && !defined(_IA64_)
INT64 InterlockedCompareExchange64(IN OUT INT64 *Destination, IN INT64 Exchange, IN INT64 Comparand)
{
	INT64 Res;
    __asm {
       mov  eax, dword ptr Comparand
       mov  edx, dword ptr Comparand+4
       mov  ebx, dword ptr Exchange
       mov  ecx, dword ptr Exchange+4
	   mov  edi, Destination
       // cmp edx:eax xchg ecx:ebx
       lock cmpxchg8b qword ptr [edi]
	   mov dword ptr Res+4, edx
	   mov dword ptr Res, eax
    }
	return Res;
}
#endif 

PVOID x86::InjectCode(PVOID Module, PBYTE Code, PBYTE NewCode, PVOID *PrevCode, _Trampoline *Trampoline)
{
	InjectContext *Context = new InjectContext;
	if ( Context == NULL ) {
		return NULL;
	}
	Context->Type = injNone;
	Context->Code = Code;
	Context->Trampoline = Trampoline;

	hin::MAPHANDLE TrampHandle = NULL, CodeHandle = NULL, RvaHandle = NULL;

    PBYTE RealCode;
    _Trampoline *RealTrampoline = (_Trampoline *) hin::MapForWrite(&TrampHandle, Trampoline, sizeof _Trampoline);
	if ( RealTrampoline == NULL ) {
		delete Context;
        return NULL;
	}

	static const BYTE Prefix32[] = {
		0xe9, 0x00, 0x00, 0x00, 0x00								// jmp NewCode
	};

	static const BYTE Prefix64[] =  {
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, rip
		0x48, 0x39, 0x04, 0x24,										// cmp [rsp], eax
		0x74, 0x0c,													// jz pass
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, rva
		0xff, 0xe0,													// jmp rax
		0x58,														// pass: pop rax
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, NewCode
		0xff, 0xe0													// jmp rax
	};
	static const BYTE Sufix32[] = {0xe9, 0x00, 0x00, 0x00, 0x00 };
	static const BYTE Sufix64[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
	BYTE Redirect32[] = {0xe9, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc };	
	BYTE Redirect64[] = {0xe8, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc };
	ULONG InjectSize = State.Width == cwt64 ? 5 : 5;
	ULONG CopyLength = 0;
	
	//
	// Create prefix
	//
	if ( State.Width == cwt32 ) {

		memcpy(RealTrampoline->Prefix, Prefix32, sizeof Prefix32);
		*(PLONG_PTR)&RealTrampoline->Prefix[1] = NewCode - ( Trampoline->Prefix + sizeof Prefix32 );

	} else
	if ( State.Width == cwt64 ) {
		//
		// Get first imported function
		//
		Context->RvaOffset = (PBYTE) hin::GetImportedFunc(Module, "");
		if ( Context->RvaOffset == NULL ) {
			goto cleanup;
		}
		Context->Rva = *(INT64 *)Context->RvaOffset;

		memcpy(RealTrampoline->Prefix, Prefix64, sizeof Prefix64);
		*(PBYTE *)&RealTrampoline->Prefix[2] = Code + InjectSize;
		*(INT64 *)&RealTrampoline->Prefix[18] = Context->Rva;
		*(PBYTE *)&RealTrampoline->Prefix[31] = NewCode;
	}
	//
	// Copy the required number of instructions to trampoline
	//
	while ( CopyLength < InjectSize ) {
		ULONG Length = Parse(Code+CopyLength);
		if ( Length == 0 ) {
			goto cleanup;
		}

		if ( ( State.ParseFlags & INS_RET ) && ( ( CopyLength + Length ) < InjectSize ) ) {
			goto cleanup;
		}

		memcpy(RealTrampoline->Sufix+CopyLength, Code+CopyLength, Length);
		//
		// Adjusting relative offsets
		//
		if ( ( State.Params[0] & 0xffffff00 ) == J ) {
			PBYTE Offset = Code + CopyLength + Length;
			switch ( State.JLength ) {
				case 1:
					Offset += *PCHAR(Code + CopyLength + State.JOffset);
					break;
				case 2:
					Offset += *PSHORT(Code + CopyLength + State.JOffset);
					break;
				case 4:
					Offset += *PLONG(Code + CopyLength + State.JOffset);
					break;
			}

			LONG_PTR NewRelative = Offset - ( Trampoline->Sufix + CopyLength + Length );
			LONG_PTR Absolute = NewRelative > 0 ? NewRelative : -NewRelative;

			if ( Absolute >> (8*State.JLength - 1) ) {
				goto cleanup;
			}

			switch ( State.JLength ) {
				case 1:
					*PBYTE(RealTrampoline->Sufix + CopyLength + State.JOffset) = BYTE(NewRelative);
					break;
				case 2:
					*PUSHORT(RealTrampoline->Sufix + CopyLength + State.JOffset) = USHORT(NewRelative);
					break;
				case 4:
					*PULONG(RealTrampoline->Sufix + CopyLength + State.JOffset) = ULONG(NewRelative);
					break;
			}
		}

		CopyLength += Length;
	}

	//
	// Create final jump in trampoline
	//
	if ( State.Width == cwt32 ) {
		memcpy(RealTrampoline->Sufix + CopyLength, Sufix32, sizeof  Sufix32);
		*(PLONG_PTR)(RealTrampoline->Sufix + CopyLength + 1) =
			Code + CopyLength - ( Trampoline->Sufix + CopyLength + sizeof Sufix32 );
	} else
	if ( State.Width == cwt64 ) {
		memcpy(RealTrampoline->Sufix + CopyLength, Sufix64, sizeof  Sufix64);
		*(PBYTE *)(RealTrampoline->Sufix + CopyLength + 2) = Code + CopyLength;
	}

	hin::UnMap(TrampHandle);
	TrampHandle = NULL;
	//
	// Point to prev code before patch
	//
	*PrevCode = Trampoline->Sufix;

    RealCode = (PBYTE) hin::MapForWrite(&CodeHandle, Code, sizeof _Trampoline);
	if ( RealCode == NULL ) {
		goto cleanup;
	}
	//
	// Insert redirection code
	//
	memcpy(&Context->Content, Code, sizeof Context->Content);

	if ( State.Width == cwt32 ) {
		*(PLONG_PTR)&Redirect32[1] = Trampoline->Prefix - ( Code + InjectSize );

		if ( CopyLength < sizeof Redirect32 ) 
			memcpy(Redirect32+CopyLength, (PBYTE)&Context->Content+CopyLength, sizeof Redirect32 - CopyLength);

		if ( InterlockedCompareExchange64((INT64 *) RealCode, *(INT64 *)Redirect32, Context->Content )
			!= Context->Content ) {

			goto cleanup;
		}
		Context->AdjustedCode = *(INT64 *)Redirect32;
		Context->Type = injJump;
	} else
	if ( State.Width == cwt64 ) {

		*(PLONG)&Redirect64[1] = (LONG) ( Context->RvaOffset - ( Code + InjectSize ) );

        PBYTE RealRvaOffset = (PBYTE) hin::MapForWrite(&RvaHandle, Context->RvaOffset, sizeof INT64);
		if ( RealRvaOffset == NULL ) {
			goto cleanup;
		}
	
		if ( InterlockedCompareExchange64((INT64 *)RealRvaOffset, (INT64)Trampoline, Context->Rva ) != 
			Context->Rva ) {
			goto cleanup;
		}

		hin::UnMap(RvaHandle);
		RvaHandle = NULL;

		if ( CopyLength < sizeof Redirect64 ) 
			memcpy(Redirect64+CopyLength, (PBYTE)&Context->Content+CopyLength, sizeof Redirect64 - CopyLength);

		if ( InterlockedCompareExchange64((INT64 *) RealCode, *(INT64 *)Redirect64, Context->Content )
			!= Context->Content ) {

			goto cleanup;
		}

		Context->AdjustedRva = (INT64)Trampoline;
		Context->AdjustedCode = *(INT64 *)Redirect64;
		Context->Type = injImportCall;
	}

	hin::UnMap(CodeHandle);
	CodeHandle = NULL;

cleanup:
	if ( CodeHandle != NULL ) hin::UnMap(CodeHandle);
	if ( TrampHandle != NULL ) hin::UnMap(TrampHandle);
	if ( RvaHandle != NULL ) hin::UnMap(RvaHandle);
	if ( Context != NULL && Context->Type == injNone ) {
		delete Context;
		Context = NULL;
	}

	return Context;
}

x86::_Trampoline *x86::RemoveInjection(InjectContext *Context)
{
	hin::MAPHANDLE MapHandle;
    PBYTE RealCode = (PBYTE) hin::MapForWrite(&MapHandle, Context->Code, sizeof Context->Content);
	if ( RealCode == NULL ) return NULL;

	if ( InterlockedCompareExchange64((INT64 *) RealCode, Context->Content, Context->AdjustedCode ) 
		 != Context->AdjustedCode ) {
		
		hin::UnMap(MapHandle);
		return NULL;
	}
	hin::UnMap(MapHandle);

	if ( Context->Type == injImportCall ) {

        PBYTE RealRvaOffset = (PBYTE) hin::MapForWrite(&MapHandle, Context->RvaOffset, sizeof Context->Rva);
		if ( RealRvaOffset == NULL ) return NULL;

		if ( InterlockedCompareExchange64((INT64 *)RealRvaOffset, Context->Rva, Context->AdjustedRva ) 
			 != Context->AdjustedRva ) {

			hin::UnMap(MapHandle);
			return NULL;
		}
		hin::UnMap(MapHandle);
	}

	_Trampoline *Tramp = Context->Trampoline;
	delete Context;

	return Tramp;
}