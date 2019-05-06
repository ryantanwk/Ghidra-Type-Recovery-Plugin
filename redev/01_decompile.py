#!/usr/bin/env python3
import binascii
import fcntl
import os
import subprocess
import os

from contextlib import contextmanager

command_start = b'\0\0\1\2'
command_end = b'\0\0\1\3'
query_response_start= b'\0\0\1\10'
query_response_end = b'\0\0\1\t'
string_start = b'\0\0\1\16'
string_end = b'\0\0\1\17'
exception_start = b'\0\0\1\12'
exception_end = b'\0\0\1\13'
byte_start = '\0\0\1\14'
byte_end = '\0\0\1\15'

GHIDRA_PATH='/home/ws/repo/ghidra/build/dist/ghidra_9.1-DEV'

class Decompiler():
    ops = [
        b'segment',
        b'in',
        b'out',
        b'sysenter',
        b'sysexit',
        b'syscall',
        b'sysret',
        b'swapgs',
        b'invlpg',
        b'rdtscp',
        b'mwait',
        b'monitor',
        b'swi',
        b'LOCK',
        b'clgi',
        b'stgi',
        b'vmload',
        b'vmmcall',
        b'vmrun',
        b'vmsave',
        b'invept',
        b'invvpid',
        b'vmcall',
        b'vmclear',
        b'vmlaunch',
        b'vmresume',
        b'vmptrld',
        b'vmptrst',
        b'vmread',
        b'vmwrite',
        b'vmxoff',
        b'vmxon',
        b'clflush',
        b'bad_CMPXCHG8B',
        b'cpuid',
        b'cpuid_basic_info',
        b'cpuid_Version_info',
        b'cpuid_cache_tlb_info',
        b'cpuid_serial_info',
        b'cpuid_Deterministic_Cache_Parameters_info',
        b'cpuid_MONITOR_MWAIT_Features_info',
        b'cpuid_Thermal_Power_Management_info',
        b'cpuid_Extended_Feature_Enumeration_info',
        b'cpuid_Direct_Cache_Access_info',
        b'cpuid_Architectural_Performance_Monitoring_info',
        b'cpuid_Extended_Topology_info',
        b'cpuid_Processor_Extended_States_info',
        b'cpuid_Quality_of_Service_info',
        b'cpuid_brand_part1_info',
        b'cpuid_brand_part2_info',
        b'cpuid_brand_part3_info',
        b'GlobalDescriptorTableRegister',
        b'InterruptDescriptorTableRegister',
        b'LocalDescriptorTableRegister',
        b'SegmentLimit',
        b'TaskRegister',
        b'swap_bytes',
        b'rdmsr',
        b'rdpmc',
        b'rdtsc',
        b'smm_restore_state',
        b'wrmsr',
        b'xsave',
        b'xrstor',
        b'f2xm1',
        b'fcos',
        b'fldenv',
        b'fpatan',
        b'fptan',
        b'fscale',
        b'fsin',
        b'addpd',
        b'cmppd',
        b'cmpps',
        b'cmpsd',
        b'cmpss',
        b'divpd',
        b'divps',
        b'lddqu',
        b'maskmovdqu',
        b'maxpd',
        b'maxps',
        b'maxsd',
        b'maxss',
        b'minpd',
        b'minps',
        b'minsd',
        b'minss',
        b'movdq2q',
        b'movhlps',
        b'movhpd',
        b'movhps',
        b'movlhps',
        b'movlpd',
        b'movlps',
        b'movmskpd',
        b'movmskps',
        b'orpd',
        b'orps',
        b'packsswb',
        b'packssdw',
        b'packuswb',
        b'pabsb',
        b'pabsw',
        b'pabsd',
        b'paddsb',
        b'paddsw',
        b'paddusb',
        b'paddusw',
        b'pavgb',
        b'pavgw',
        b'pcmpeqb',
        b'phaddd',
        b'phaddw',
        b'phaddsw',
        b'phsubd',
        b'phsubw',
        b'phsubsw',
        b'pinsrw',
        b'pmaddubsw',
        b'pmaddwd',
        b'pmaxsw',
        b'pmaxub',
        b'pminsw',
        b'pminub',
        b'pmovmskb',
        b'pmulhrsw',
        b'pmulhuw',
        b'pmulhw',
        b'pmullw',
        b'pmuludq',
        b'psadbw',
        b'pshufb',
        b'pshufhw',
        b'pshuflw',
        b'pshufw',
        b'psignb',
        b'psignw',
        b'psignd',
        b'pslldq',
        b'psllw',
        b'pslld',
        b'psllq',
        b'psraw',
        b'psrlw',
        b'psrld',
        b'psrlq',
        b'psubb',
        b'psubd',
        b'psubq',
        b'psubsb',
        b'psubsw',
        b'psubusb',
        b'psubusw',
        b'punpcklqdq',
        b'rcpps',
        b'rcpss',
        b'rsqrtps',
        b'rsqrtss',
        b'shufpd',
        b'sqrtpd',
        b'sqrtps',
        b'sqrtsd',
        b'sqrtss',
        b'subpd',
        b'subps',
        b'xstore_available',
        b'xstore',
        b'xcrypt_ecb',
        b'xcrypt_cbc',
        b'xcrypt_ctr',
        b'xcrypt_cfb',
        b'xcrypt_ofb',
        b'montmul',
        b'xsha1',
        b'xsha256',
        b'mpsadbw',
        b'phminposuw',
        b'pmuldq',
        b'pmulld',
        b'dpps',
        b'dppd',
        b'blendps',
        b'blendpd',
        b'blendvps',
        b'blendvpd',
        b'pblendvb',
        b'pblendw',
        b'pminsb',
        b'pminuw',
        b'pminud',
        b'pminsd',
        b'pmaxsb',
        b'pmaxuw',
        b'pmaxud',
        b'pmaxsd',
        b'roundps',
        b'roundss',
        b'roundpd',
        b'roundsd',
        b'insertps',
        b'pinsrb',
        b'pinsrd',
        b'pinsrq',
        b'extractps',
        b'pextrb',
        b'pextrd',
        b'pextrq',
        b'pmovsxbw',
        b'pmovsxbd',
        b'pmovsxbq',
        b'pmovsxwd',
        b'pmovsxwq',
        b'pmovsxdq',
        b'pmovzxbw',
        b'pmovzxbd',
        b'pmovzxbq',
        b'pmovzxwd',
        b'pmovzxwq',
        b'pmovzxdq',
        b'ptest',
        b'pcmpeqq',
        b'packusdw',
        b'movntdqa',
        b'crc32',
        b'pcmpestri',
        b'pcmpestrm',
        b'pcmpistri',
        b'pcmpistrm',
        b'pcmpgtq',
        b'popcnt',
        b'aesdec',
        b'aesdeclast',
        b'aesenc',
        b'aesenclast',
        b'aesimc',
        b'aeskeygenassist',
        b'PackedIntToFloatingDwordConv',
        b'PackedFloatingToIntDwordConv',
        b'PackedFloatingCompareGE',
        b'PackedFloatingCompareGT',
        b'PackedFloatingCompareEQ',
        b'PackedFloatingAccumulate',
        b'PackedFloatingADD',
        b'PackedFloatingSUB',
        b'PackedFloatingSUBR',
        b'PackedFloatingMIN',
        b'PackedFloatingMAX',
        b'PackedFloatingMUL',
        b'FloatingReciprocalAprox',
        b'PackedFloatingReciprocalSQRAprox',
        b'PackedFloatingReciprocalIter1',
        b'PackedFloatingReciprocalSQRIter1',
        b'PackedFloatingReciprocalIter2',
        b'PackedAverageUnsignedBytes',
        b'PackedAverageHighRoundedWord',
        b'FastExitMediaState',
        b'PackedFloatingToIntWord',
        b'PackedIntToFloatingWord',
        b'PackedFloatingNegAccumulate',
        b'PackedFloatingPosNegAccumulate',
        b'PackedSwapDWords',
        b'MaskedMoveQWord',
        b'vaddpd_avx',
        b'vaddps_avx',
        b'vaddsd_avx',
        b'vaddss_avx',
        b'vaddsubpd_avx',
        b'vaddsubps_avx',
        b'vandpd_avx',
        b'vandps_avx',
        b'vandnpd_avx',
        b'vandnps_avx',
        b'vblendpd_avx',
        b'vblendps_avx',
        b'vblendvpd_avx',
        b'vblendvps_avx',
        b'vcmppd_avx',
        b'vcmpps_avx',
        b'vcmpsd_avx',
        b'vcmpss_avx',
        b'vcomisd_avx',
        b'vcomiss_avx',
        b'vcvtdq2pd_avx',
        b'vcvtdq2ps_avx',
        b'vcvtpd2dq_avx',
        b'vcvtpd2ps_avx',
        b'vcvtps2dq_avx',
        b'vcvtps2pd_avx',
        b'vcvtsd2si_avx',
        b'vcvtsd2ss_avx',
        b'vcvtsi2sd_avx',
        b'vcvtsi2ss_avx',
        b'vcvtss2sd_avx',
        b'vcvtss2si_avx',
        b'vcvttpd2dq_avx',
        b'vcvttps2dq_avx',
        b'vcvttsd2si_avx',
        b'vcvttss2si_avx',
        b'vdivpd_avx',
        b'vdivps_avx',
        b'vdivsd_avx',
        b'vdivss_avx',
        b'vdppd_avx',
        b'vdpps_avx',
        b'vextractps_avx',
        b'vhaddpd_avx',
        b'vhaddps_avx',
        b'vhsubpd_avx',
        b'vhsubps_avx',
        b'vinsertps_avx',
        b'vlddqu_avx',
        b'vldmxcsr_avx',
        b'vmaskmovdqu_avx',
        b'vmaxpd_avx',
        b'vmaxps_avx',
        b'vmaxsd_avx',
        b'vmaxss_avx',
        b'vminpd_avx',
        b'vminps_avx',
        b'vminsd_avx',
        b'vminss_avx',
        b'vmovapd_avx',
        b'vmovaps_avx',
        b'vmovd_avx',
        b'vmovq_avx',
        b'vmovddup_avx',
        b'vmovdqa_avx',
        b'vmovdqu_avx',
        b'vmovhlps_avx',
        b'vmovhpd_avx',
        b'vmovhps_avx',
        b'vmovlhps_avx',
        b'vmovlpd_avx',
        b'vmovlps_avx',
        b'vmovmskpd_avx',
        b'vmovmskps_avx',
        b'vmovntdqa_avx',
        b'vmovntdq_avx',
        b'vmovntpd_avx',
        b'vmovntps_avx',
        b'vmovshdup_avx',
        b'vmovsldup_avx',
        b'vmovss_avx',
        b'vmovupd_avx',
        b'vmpsadbw_avx',
        b'vmulpd_avx',
        b'vmulps_avx',
        b'vmulsd_avx',
        b'vmulss_avx',
        b'vorpd_avx',
        b'vorps_avx',
        b'vpabsb_avx',
        b'vpabsw_avx',
        b'vpabsd_avx',
        b'vpacksswb_avx',
        b'vpackssdw_avx',
        b'vpackusdw_avx',
        b'vpackuswb_avx',
        b'vpaddb_avx',
        b'vpaddw_avx',
        b'vpaddd_avx',
        b'vpaddq_avx',
        b'vpaddsb_avx',
        b'vpaddsw_avx',
        b'vpaddusb_avx',
        b'vpaddusw_avx',
        b'vpalignr_avx',
        b'vpand_avx',
        b'vpandn_avx',
        b'vpavgb_avx',
        b'vpavgw_avx',
        b'vpblendvb_avx',
        b'vpblendw_avx',
        b'vpcmpeqb_avx',
        b'vpcmpeqw_avx',
        b'vpcmpeqd_avx',
        b'vpcmpeqq_avx',
        b'vpcmpestri_avx',
        b'vpcmpestrm_avx',
        b'vpcmpgtb_avx',
        b'vpcmpgtw_avx',
        b'vpcmpgtd_avx',
        b'vpcmpgtq_avx',
        b'vpcmpistri_avx',
        b'vpcmpistrm_avx',
        b'vpextrb_avx',
        b'vpextrd_avx',
        b'vpextrq_avx',
        b'vpextrw_avx',
        b'vphaddw_avx',
        b'vphaddd_avx',
        b'vphaddsw_avx',
        b'vphminposuw_avx',
        b'vphsubw_avx',
        b'vphsubd_avx',
        b'vphsubsw_avx',
        b'vpinsrb_avx',
        b'vpinsrd_avx',
        b'vpinsrq_avx',
        b'vpinsrw_avx',
        b'vpmaddubsw_avx',
        b'vpmaddwd_avx',
        b'vpmaxsb_avx',
        b'vpmaxsw_avx',
        b'vpmaxsd_avx',
        b'vpmaxub_avx',
        b'vpmaxuw_avx',
        b'vpmaxud_avx',
        b'vpminsb_avx',
        b'vpminsw_avx',
        b'vpminsd_avx',
        b'vpminub_avx',
        b'vpminuw_avx',
        b'vpminud_avx',
        b'vpmovmskb_avx',
        b'vpmovsxbw_avx',
        b'vpmovsxbd_avx',
        b'vpmovsxbq_avx',
        b'vpmovsxwd_avx',
        b'vpmovsxwq_avx',
        b'vpmovsxdq_avx',
        b'vpmovzxbw_avx',
        b'vpmovzxbd_avx',
        b'vpmovzxbq_avx',
        b'vpmovzxwd_avx',
        b'vpmovzxwq_avx',
        b'vpmovzxdq_avx',
        b'vpmuldq_avx',
        b'vpmulhrsw_avx',
        b'vpmulhuw_avx',
        b'vpmulhw_avx',
        b'vpmulld_avx',
        b'vpmullw_avx',
        b'vpmuludq_avx',
        b'vpor_avx',
        b'vpsadbw_avx',
        b'vpshufb_avx',
        b'vpshufd_avx',
        b'vpshufhw_avx',
        b'vpshuflw_avx',
        b'vpsignb_avx',
        b'vpsignw_avx',
        b'vpsignd_avx',
        b'vpslldq_avx',
        b'vpsllw_avx',
        b'vpslld_avx',
        b'vpsllq_avx',
        b'vpsraw_avx',
        b'vpsrad_avx',
        b'vpsrldq_avx',
        b'vpsrlw_avx',
        b'vpsrld_avx',
        b'vpsrlq_avx',
        b'vpsubb_avx',
        b'vpsubw_avx',
        b'vpsubd_avx',
        b'vpsubq_avx',
        b'vpsubsb_avx',
        b'vpsubsw_avx',
        b'vpsubusb_avx',
        b'vpsubusw_avx',
        b'vptest_avx',
        b'vpunpckhbw_avx',
        b'vpunpckhwd_avx',
        b'vpunpckhdq_avx',
        b'vpunpckhqdq_avx',
        b'vpunpcklbw_avx',
        b'vpunpcklwd_avx',
        b'vpunpckldq_avx',
        b'vpunpcklqdq_avx',
        b'vpxor_avx',
        b'vrcpps_avx',
        b'vrcpss_avx',
        b'vroundpd_avx',
        b'vroundps_avx',
        b'vroundsd_avx',
        b'vroundss_avx',
        b'vrsqrtps_avx',
        b'vrsqrtss_avx',
        b'vshufpd_avx',
        b'vshufps_avx',
        b'vsqrtpd_avx',
        b'vsqrtps_avx',
        b'vsqrtsd_avx',
        b'vsqrtss_avx',
        b'vstmxcsr_avx',
        b'vsubpd_avx',
        b'vsubps_avx',
        b'vsubsd_avx',
        b'vsubss_avx',
        b'vucomisd_avx',
        b'vucomiss_avx',
        b'vunpckhpd_avx',
        b'vunpckhps_avx',
        b'vunpcklpd_avx',
        b'vunpcklps_avx',
        b'vbroadcastss_avx',
        b'vbroadcastsd_avx',
        b'vbroadcastf128_avx',
        b'vextractf128_avx',
        b'vinsertf128_avx',
        b'vmaskmovps_avx',
        b'vmaskmovpd_avx',
        b'vperm2f128_avx',
        b'vpermilpd_avx',
        b'vpermilps_avx',
        b'vtestps_avx',
        b'vtestpd_avx',
        b'vzeroall_avx',
        b'vzeroupper_avx',
        b'vxorpd_avx',
        b'vxorps_avx',
        b'vmovntdqa_avx2',
        b'vmpsadbw_avx2',
        b'vpabsb_avx2',
        b'vpabsw_avx2',
        b'vpabsd_avx2',
        b'vpacksswb_avx2',
        b'vpackssdw_avx2',
        b'vpackusdw_avx2',
        b'vpackuswb_avx2',
        b'vpaddb_avx2',
        b'vpaddw_avx2',
        b'vpaddd_avx2',
        b'vpaddq_avx2',
        b'vpaddsb_avx2',
        b'vpaddsw_avx2',
        b'vpaddusb_avx2',
        b'vpaddusw_avx2',
        b'vpalignr_avx2',
        b'vpand_avx2',
        b'vpandn_avx2',
        b'vpavgb_avx2',
        b'vpavgw_avx2',
        b'vpblendvb_avx2',
        b'vpblendw_avx2',
        b'vpcmpeqb_avx2',
        b'vpcmpeqw_avx2',
        b'vpcmpeqd_avx2',
        b'vpcmpeqq_avx2',
        b'vpcmpgtb_avx2',
        b'vpcmpgtw_avx2',
        b'vpcmpgtd_avx2',
        b'vpcmpgtq_avx2',
        b'vphaddw_avx2',
        b'vphaddd_avx2',
        b'vphaddsw_avx2',
        b'vphsubw_avx2',
        b'vphsubd_avx2',
        b'vphsubsw_avx2',
        b'vpmaddubsw_avx2',
        b'vpmaddwd_avx2',
        b'vpmaxsb_avx2',
        b'vpmaxsw_avx2',
        b'vpmaxsd_avx2',
        b'vpmaxub_avx2',
        b'vpmaxuw_avx2',
        b'vpmaxud_avx2',
        b'vpminsb_avx2',
        b'vpminsw_avx2',
        b'vpminsd_avx2',
        b'vpminub_avx2',
        b'vpminuw_avx2',
        b'vpminud_avx2',
        b'vpmovmskb_avx2',
        b'vpmovsxbw_avx2',
        b'vpmovsxbd_avx2',
        b'vpmovsxbq_avx2',
        b'vpmovsxwd_avx2',
        b'vpmovsxwq_avx2',
        b'vpmovsxdq_avx2',
        b'vpmovzxbw_avx2',
        b'vpmovzxbd_avx2',
        b'vpmovzxbq_avx2',
        b'vpmovzxwd_avx2',
        b'vpmovzxwq_avx2',
        b'vpmovzxdq_avx2',
        b'vpmuldq_avx2',
        b'vpmulhrsw_avx2',
        b'vpmulhuw_avx2',
        b'vpmulhw_avx2',
        b'vpmulld_avx2',
        b'vpmullw_avx2',
        b'vpmuludq_avx2',
        b'vpor_avx2',
        b'vpsadbw_avx2',
        b'vpshufb_avx2',
        b'vpshufd_avx2',
        b'vpshufhw_avx2',
        b'vpshuflw_avx2',
        b'vpsignb_avx2',
        b'vpsignw_avx2',
        b'vpsignd_avx2',
        b'vpslldq_avx2',
        b'vpsllw_avx2',
        b'vpslld_avx2',
        b'vpsllq_avx2',
        b'vpsraw_avx2',
        b'vpsrad_avx2',
        b'vpsrldq_avx2',
        b'vpsrlw_avx2',
        b'vpsrld_avx2',
        b'vpsrlq_avx2',
        b'vpsubb_avx2',
        b'vpsubw_avx2',
        b'vpsubd_avx2',
        b'vpsubq_avx2',
        b'vpsubsb_avx2',
        b'vpsubsw_avx2',
        b'vpsubusb_avx2',
        b'vpsubusw_avx2',
        b'vpunpckhbw_avx2',
        b'vpunpckhwd_avx2',
        b'vpunpckhdq_avx2',
        b'vpunpckhqdq_avx2',
        b'vpunpcklbw_avx2',
        b'vpunpcklwd_avx2',
        b'vpunpckldq_avx2',
        b'vpunpcklqdq_avx2',
        b'vpxor_avx2',
        b'vextracti128_avx2',
        b'vpblendd_avx2',
        b'vpbroadcastb_avx2',
        b'vpbroadcastw_avx2',
        b'vpbroadcastd_avx2',
        b'vpbroadcastq_avx2',
        b'vbroadcasti128_avx2',
        b'vperm2i128_avx2',
        b'vpermd_avx2',
        b'vpermpd_avx2',
        b'vpermps_avx2',
        b'vpermq_avx2',
        b'vpmaskmovd_avx2',
        b'vpmaskmovq_avx2',
        b'vpsllvd_avx2',
        b'vpsllvq_avx2',
        b'vpsravd_avx2',
        b'vpsrlvd_avx2',
        b'vpsrlvq_avx2',
        b'vinserti128',
        b'vgatherdpd',
        b'vgatherqpd',
        b'vgatherdps',
        b'vgatherqps',
        b'vpgatherdd',
        b'vpgatherqd',
        b'vpgatherdq',
        b'vpgatherqq',
        b'rdrand',
        b'rdrandIsValid',
        b'rdseed',
        b'rdseedIsValid',
        b'encls_ecreate',
        b'encls_eadd',
        b'encls_einit',
        b'encls_einit_ZF',
        b'encls_eremove',
        b'encls_eremove_ZF',
        b'encls_edbgrd',
        b'encls_edbgrd_RBX',
        b'encls_edbgwr',
        b'encls_eextend',
        b'encls_eldb',
        b'encls_eldb_ZF',
        b'encls_eldu',
        b'encls_eldu_ZF',
        b'encls_eblock',
        b'encls_eblock_ZF',
        b'encls_epa',
        b'encls_ewb',
        b'encls_ewb_ZF',
        b'encls_ewb_CF',
        b'encls_etrack',
        b'encls_etrack_ZF',
        b'encls_eaug',
        b'encls_emodpr',
        b'encls_emodpr_ZF',
        b'encls_emodt',
        b'encls_emodt_ZF',
        b'encls_unknown',
        b'enclu_ereport',
        b'enclu_egetkey',
        b'enclu_egetkey_ZF',
        b'enclu_eenter_EAX',
        b'enclu_eenter_RCX',
        b'enclu_eenter_TF',
        b'enclu_eresume',
        b'enclu_eexit',
        b'enclu_eexit_TF',
        b'enclu_eaccept',
        b'enclu_eaccept_ZF',
        b'enclu_emodpe',
        b'enclu_eacceptcopy',
        b'enclu_eacceptcopy_ZF',
        b'enclu_unknown',
        b'clwb',
        b'clflushopt',
        b'br_exception',
        b'sha1rnds4_sha',
        b'sha1nexte_sha',
        b'sha1msg1_sha',
        b'sha1msg2_sha',
        b'sha256rnds2_sha',
        b'sha256msg1_sha',
        b'sha256msg2_sha'
    ]

    # ./Ghidra/Processors/x86/data/languages/x86-64.sla
    registers = {
        b'RSP': b'<addr space=\"register\" offset=\"0x20\" size=\"8\"/>\n',
        b'XMM0': b'<addr space=\"register\" offset=\"0x1200\" size=\"16\"/>\n',
        b'XMM1': b'<addr space=\"register\" offset=\"0x1220\" size=\"16\"/>\n',
        b'XMM2': b'<addr space=\"register\" offset=\"0x1240\" size=\"16\"/>\n',
        b'XMM3': b'<addr space=\"register\" offset=\"0x1260\" size=\"16\"/>\n',
        b'XMM4': b'<addr space=\"register\" offset=\"0x1280\" size=\"16\"/>\n',
        b'XMM5': b'<addr space=\"register\" offset=\"0x12a0\" size=\"16\"/>\n',
        b'XMM6': b'<addr space=\"register\" offset=\"0x12c0\" size=\"16\"/>\n',
        b'XMM7': b'<addr space=\"register\" offset=\"0x12e0\" size=\"16\"/>\n',
        b'RDI': b'<addr space=\"register\" offset=\"0x38\" size=\"8\"/>\n',
        b'RSI': b'<addr space=\"register\" offset=\"0x30\" size=\"8\"/>\n',
        b'RDX': b'<addr space=\"register\" offset=\"0x10\" size=\"8\"/>\n',
        b'RCX': b'<addr space=\"register\" offset=\"0x8\" size=\"8\"/>\n',
        b'R8': b'<addr space=\"register\" offset=\"0x80\" size=\"8\"/>\n',
        b'R9': b'<addr space=\"register\" offset=\"0x88\" size=\"8\"/>\n',
        b'RAX': b'<addr space=\"register\" offset=\"0x0\" size=\"8\"/>\n',
        b'RBX': b'<addr space=\"register\" offset=\"0x18\" size=\"8\"/>\n',
        b'RBP': b'<addr space=\"register\" offset=\"0x28\" size=\"8\"/>\n',
        b'R12': b'<addr space=\"register\" offset=\"0xa0\" size=\"8\"/>\n',
        b'R13': b'<addr space=\"register\" offset=\"0xa8\" size=\"8\"/>\n',
        b'R14': b'<addr space=\"register\" offset=\"0xb0\" size=\"8\"/>\n',
        b'R15': b'<addr space=\"register\" offset=\"0xb8\" size=\"8\"/>\n',
        b'XMM0_Qa': b'<addr space=\"register\" offset=\"0x1200\" size=\"8\"/>\n',
        b'XMM1_Qa': b'<addr space=\"register\" offset=\"0x1220\" size=\"8\"/>\n',
        b'XMM2_Qa': b'<addr space=\"register\" offset=\"0x1240\" size=\"8\"/>\n',
        b'XMM3_Qa': b'<addr space=\"register\" offset=\"0x1260\" size=\"8\"/>\n',
        b'DF': b'<addr space=\"register\" offset=\"0x20a\" size=\"1\"/>\n',
    }


    def __init__(self):
        p = subprocess.Popen([os.path.join(GHIDRA_PATH, 'Ghidra/Features/Decompiler/os/linux64/decompile')],stdout=subprocess.PIPE,stdin=subprocess.PIPE, bufsize=4096)
        self.p = p
        self.stdin = p.stdin
        self.stdout = p.stdout

    def write_bytes(self, out):
        self.p.stdin.write(string_start)
        sz = len(out)
        self.stdin.write(bytes(chr((sz & 0x3f) + 0x20), 'ascii'))
        sz = sz >> 6
        self.stdin.write(bytes(chr((sz & 0x3f) + 0x20), 'ascii'))
        sz = sz >> 6
        self.stdin.write(bytes(chr((sz & 0x3f) + 0x20), 'ascii'))
        sz = sz >> 6
        self.stdin.write(bytes(chr((sz & 0x3f) + 0x20), 'ascii'))
        self.p.stdin.write(out)
        self.p.stdin.write(string_end)

    def write_string(self, s):
        self.p.stdin.write(string_start + s + string_end)

    GihdraAlignmentError = Exception("Ghidra/decompiler alignment error")

    def read_query_string(self):
        type_ = self.read_to_burst()
        if type_ != 14:
            raise GihdraAlignmentError

        (type_, buff) = self.read_to_buffer()

        if type_ != 15:
            raise GihdraAlignmentError

        return buff

    def read_response(self):
        self.read_to_response()

        buf = None

        type_ = self.read_to_burst()
        while type_ != 7:
            print ('read_response', type_)
            if type_ == 4:
                print("read_query_string")
                name = self.read_query_string()
                print("query_string", name)
                print(name)
                if name == b'getUserOpName':
                    index = int(self.read_query_string())
                    if index>=len(self.ops):
                        self.stdin.write(query_response_start)
                        self.write_string(b"")
                        self.stdin.write(query_response_end)
                    else:
                        self.stdin.write(query_response_start)
                        print (index, self.ops[index])
                        self.write_string(self.ops[index])
                        self.stdin.write(query_response_end)
                elif name == b'getRegister':
                    register = self.read_query_string()
                    self.stdin.write(query_response_start)
                    self.write_string(self.registers[register])
                    self.stdin.write(query_response_end)
                elif name == b'getComments':
                    addr = self.read_query_string()
                    flags = self.read_query_string()
                    self.stdin.write(query_response_start)
                    self.write_string(b"<commentdb>\\n</commentdb>")
                    self.stdin.write(query_response_end)
                elif name == b'getTrackedRegisters':
                    addr = self.read_query_string()
                    self.stdin.write(query_response_start)
                    self.write_string(b"<tracked_pointset space=\"ram\" offset=\"0x413c8c\">\n<set space=\"register\" offset=\"0x20a\" size=\"1\" val=\"0x0\"/>\n</tracked_pointset>\n")
                    self.stdin.write(query_response_end)
                elif name == b'getPacked':
                    addr = self.read_query_string()
                    from xml.dom import minidom
                    with minidom.parseString(addr) as dom:
                        addr = dom.getElementsByTagName('addr')[0]
                        space = addr.getAttribute('space')
                        offset = addr.getAttribute('offset')
                        print (space, offset)

                    self.stdin.write(query_response_start)

                    if '0x413c8c' == offset:
                        p.write_bytes(b"!$`\",R30`\"/%# (`!%#@`(% (`(`\"7%#+(`!%#@`(% (`(`\"4%#@`(%#@`(% (`(`\"-%#'(`!%#@`(% `(`\"+%#&(`!%#@`(% `(``")
                    elif '0x413c90' == offset:
                        p.write_bytes(b"!$`\"0R30`\"5%# (`!%#@`(% (`(`\"6%#+(`!%#@`(% (`(`\"3%#@`(%#@`(% (`(`\"-%#'(`!%#@`(% `(`\"+%#&(`!%#@`(% `(``")
                    elif '0x413c94' == offset:
                        p.write_bytes(b"!!`\"4R30`\"\"%#(*`($\"%#@`(`\"3%#@`(%#@`(% (`(`\"*#%#(*`(``")

                    self.stdin.write(query_response_end)
                elif name == b'getMappedSymbolsXML':
                    query = self.read_query_string()
                    print("getMappedSymbolsXML", query)
                    self.stdin.write(query_response_start)
                    self.write_string(b'''<result>
                        <parent>
                            <val/>
                        </parent>
                        <mapsym>
                            <function name="_fini" size="1">
                                <addr space="ram" offset="0x413c8c"/>
                                <localdb lock="false" main="stack">
                                    <scope name="_fini">
                                        <parent>
                                            <val/>
                                        </parent>
                                        <rangelist/>
                                        <symbollist></symbollist>
                                    </scope>
                                </localdb>
                                <prototype extrapop="8" model="unknown">
                                    <returnsym>
                                        <addr space="register" offset="0x0" size="1"/>
                                        <typeref name="undefined"/>
                                    </returnsym>
                                </prototype>
                            </function>
                            <addr space="ram" offset="0x413c8c"/>
                            <rangelist/>
                        </mapsym>
                    </result>''')
                    self.stdin.write(query_response_end)
                else:
                    raise Exception("NOT HANDLED")

                self.stdin.flush()
                self.read_to_burst()
            elif type_ == 14:
                print("BEGIN COMPILER OUTPUT")
                buf = b''
            elif type_ == 15:
                retbuf = buf
                buf = None
            elif type_ == 16:
                print("NESTED COMPILER OUTPUT")
                buf = b''
            elif type_ == 17:
                print (buf)
                buf = None
            else:
                raise Exception("Unknown type ({})".format(type_))

            print("X")
            if buf == None:
                type_ = self.read_to_burst()
            else:
                (type_, buf2) = self.read_to_buffer()
                print(type, buf2)
                buf = buf + buf2
            print("Y")

            # or read to buffer?

    def read_to_response(self):
        type_ = self.read_to_burst()
        while type_ & 1 == 1:
            type_ = self.read_to_burst()

        if type_ == 10:
            raise Exception("Exception")

        if type_ == 6:
            return

        raise GihdraAlignmentError

    def read_byte(self):
        buff = self.p.stdout.raw.read(1)
        if not buff:
            return None
        else:
            return buff[0]

    def read_to_buffer(self):
        buff = []

        while True:
            while True:
                b = self.read_byte()
                if b > 0:
                    buff.append(b)
                    continue

                break

            # what if b is none / -1 ?
            cur = self.read_byte()
            while cur == 0:
                cur = self.read_byte()

            if cur == 1:
                cur = self.read_byte()
                print('read_to_buff', cur, bytes(buff))
                return (cur, bytes(buff))

        raise Exception("Decompiler process died")

    def read_to_burst(self):
        cur = self.read_byte()
        while cur == 0:
            cur = self.read_byte()

        if cur == 1:
            cur = self.read_byte()
            return cur

        raise Exception("Error")

    @contextmanager
    def write_command(self):
        self.p.stdin.write(command_start)
        yield  self
        self.p.stdin.write(command_end)
        self.p.stdin.flush()

    def read(self):
        return self.p.stdout.raw.read(4096)

decompiler = Decompiler()

p = decompiler

with decompiler.write_command() as cmd:
    cmd.write_string(b'registerProgram')

    # pspecxml
    with open(os.path.join(GHIDRA_PATH, 'Ghidra/Processors/x86/data/languages/x86-64.pspec'), 'rb') as content_file:
        content = content_file.read()
        cmd.write_string(content)

    # cspecxml
    with open(os.path.join(GHIDRA_PATH, 'Ghidra/Processors/x86/data/languages/x86-64-gcc.cspec'), 'rb') as content_file:
        content = content_file.read()
        cmd.write_string(content)

    # tspecxml
    cmd.write_string(b'''<sleigh bigendian="false" uniqbase="0x10000000">
        <spaces defaultspace="ram">
            <space_unique name="unique" index="1" size="4" bigendian="false" delay="0" physical="true" global="false"/>
            <space name="ram" index="2" size="8" bigendian="false" delay="1" physical="true" global="true"/>
            <space name="register" index="3" size="4" bigendian="false" delay="0" physical="true" global="false"/>
        </spaces>
    </sleigh>''')

    # coretypesxml
    cmd.write_string(b'''<coretypes>
        <void/>
        <type name="uint" size="4" metatype="uint" id="-9223371465083307041"/>
        <type name="code" size="1" metatype="code" id="-9223371462259126427"/>
        <type name="int" size="4" metatype="int" id="-9223370945157383201"/>
        <type name="uint3" size="3" metatype="uint" id="-9223225663358771405"/>
        <type name="uint5" size="5" metatype="uint" id="-9223225663358771403"/>
        <type name="uint7" size="7" metatype="uint" id="-9223225663358771401"/>
        <type name="uint6" size="6" metatype="uint" id="-9223225661105102435"/>
        <type name="int3" size="3" metatype="int" id="-9223092562322268365"/>
        <type name="int5" size="5" metatype="int" id="-9223092562322268363"/>
        <type name="int7" size="7" metatype="int" id="-9223092562322268361"/>
        <type name="int6" size="6" metatype="int" id="-9223092560068599395"/>
        <type name="char" size="1" metatype="int" char="true" id="-9223091865880322087"/>
        <typc name="uint16" size="16" metatype="uint" id="-9185900419569365091"/>
        <type name="ushort" size="2" metatype="uint" id="-9185691276929259553"/>
        <type name="int16" size="16" metatype="int" id="-9151826554224586851"/>
        <type name="byte" size="1" metatype="uint" id="-9151688846347870363"/>
        <type name="long" size="8" metatype="int" id="-9151688846179449497"/>
        <type name="bool" size="1" metatype="bool" id="-9151688804115639865"/>
        <type name="sbyte" size="1" metatype="int" id="-9151648198777381019"/>
        <type name="short" size="2" metatype="int" id="-9151648197910059041"/>
        <type name="ulong" size="8" metatype="uint" id="-9151648190019025561"/>
        <type name="wchar_t" size="4" metatype="int" utf="true" id="-8801050271826140705"/>
        <type name="wchar16" size="2" metatype="int" utf="true" id="-8801050271826128995"/>
        <type name="double" size="8" metatype="float" id="-6087405195602966429"/>
        <type name="float10" size="10" metatype="float" id="-5894303970639204475"/>
        <type name="undefined" size="1" metatype="unknown" id="-4223139060020122321"/>
        <type name="float2" size="2" metatype="float" id="-3085472373819564389"/>
        <type name="undefined2" size="2" metatype="unknown" id="-1989071053142544393"/>
        <type name="undefined4" size="4" metatype="unknown" id="-1989071053142544391"/>
        <type name="undefined6" size="6" metatype="unknown" id="-1989071053142544389"/>
        <type name="undefined8" size="8" metatype="unknown" id="-1989071053142544387"/>
        <type name="undefined5" size="5" metatype="unknown" id="-1989071052499136175"/>
        <type name="undefined3" size="3" metatype="unknown" id="-1989071052499136173"/>
        <type name="undefined7" size="7" metatype="unknown" id="-1989071052499136169"/>
        <type name="undefined1" size="1" metatype="unknown" id="-1989071052499136163"/>
        <type name="longdouble" size="16" metatype="float" id="-1267909053971395201"/>
        <type name="float" size="4" metatype="float" id="-120139017508053025"/>
    </coretypes>''')

print(decompiler.read_response())

# set options
with decompiler.write_command() as cmd:
    cmd.write_string(b'setOptions')
    cmd.write_string(b'0')
    cmd.write_string(b'''<optionslist>
	<currentaction>
		<param1>conditionalexe</param1>
		<param2>on</param2>
	</currentaction>
	<readonly>on</readonly>
	<currentaction>
		<param1>decompile</param1>
		<param2>unreachable</param2>
		<param3>on</param3>
	</currentaction>
	<currentaction>
		<param1>decompile</param1>
		<param2>doubleprecis</param2>
		<param3>on</param3>
	</currentaction>
	<ignoreunimplemented>off</ignoreunimplemented>
	<inferconstptr>on</inferconstptr>
	<nullprinting>off</nullprinting>
	<inplaceops>off</inplaceops>
	<conventionprinting>on</conventionprinting>
	<nocastprinting>off</nocastprinting>
	<maxlinewidth>100</maxlinewidth>
	<indentincrement>2</indentincrement>
	<commentindent>20</commentindent>
	<commentstyle>c</commentstyle>
	<commentinstruction>
		<param1>header</param1>
		<param2>off</param2>
	</commentinstruction>
	<commentinstruction>
		<param1>user2</param1>
		<param2>on</param2>
	</commentinstruction>
	<commentinstruction>
		<param1>user1</param1>
		<param2>off</param2>
	</commentinstruction>
	<commentinstruction>
		<param1>user3</param1>
		<param2>off</param2>
	</commentinstruction>
	<commentinstruction>
		<param1>warning</param1>
		<param2>on</param2>
	</commentinstruction>
	<commentheader>
		<param1>header</param1>
		<param2>on</param2>
	</commentheader>
	<commentheader>
		<param1>warningheader</param1>
		<param2>on</param2>
	</commentheader>
	<integerformat>best</integerformat>
	<setlanguage>c-language</setlanguage>
	<protoeval>__stdcall</protoeval>
</optionslist>''')

print(decompiler.read_response())

print ("decompileAt")
with decompiler.write_command() as cmd:
    cmd.write_string(b'decompileAt')
    cmd.write_string(b'0')
    cmd.write_string(b'''<addr space="ram" offset="0x413c8c"/>''')

print(decompiler.read_response())

with decompiler.write_command() as cmd:
    cmd.write_string(b'flushNative')
    cmd.write_string(b'0')

print(decompiler.read_response())

with decompiler.write_command() as cmd:
    cmd.write_string(b'deregisterProgram')
    cmd.write_string(b'0')

print(decompiler.read_response())
