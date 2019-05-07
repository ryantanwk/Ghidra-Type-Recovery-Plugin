
ulong _ZN6wayobj10makebound2EPiiS0_(long lParm1,long lParm2,int iParm3,long lParm4)

{
    int iVar1;
    long lVar2;
    int iVar3;
    int iVar4;
    uint local_24;
    int local_20;

    iVar1 = *(int *)(lParm1 + 0x20);
    lVar2 = *(long *)(lParm1 + 0x80);
    local_24 = 0;
    local_20 = 0;
    do {
        if (iParm3 <= local_20) {
            return (ulong)local_24;
        }
        iVar4 = *(int *)(lParm2 + (long)local_20 * 4);
        iVar3 = (iVar4 - iVar1) + -1;
        if ((*(short *)(lVar2 + (long)iVar3 * 4) != *(short *)(lParm1 + 0xaa)) &&
                (*(short *)(*(long *)(lParm1 + 0x78) + (long)iVar3 * 2) == 0)) {
            *(int *)((long)(int)local_24 * 4 + lParm4) = iVar3;
            local_24 = local_24 + 1;
            *(undefined2 *)((long)iVar3 * 4 + lVar2) = *(undefined2 *)(lParm1 + 0xaa);
            *(undefined2 *)((long)iVar3 * 4 + lVar2 + 2) = *(undefined2 *)(lParm1 + 0xa8);
            if (*(int *)(lParm1 + 0xa4) == iVar3) {
                *(undefined *)(lParm1 + 0xa0) = 1;
                return (ulong)local_24;
            }
        }
        iVar3 = iVar4 - iVar1;
        if ((*(short *)(lVar2 + (long)iVar3 * 4) != *(short *)(lParm1 + 0xaa)) &&
                (*(short *)(*(long *)(lParm1 + 0x78) + (long)iVar3 * 2) == 0)) {
            *(int *)((long)(int)local_24 * 4 + lParm4) = iVar3;
            local_24 = local_24 + 1;
            *(undefined2 *)((long)iVar3 * 4 + lVar2) = *(undefined2 *)(lParm1 + 0xaa);
            *(undefined2 *)((long)iVar3 * 4 + lVar2 + 2) = *(undefined2 *)(lParm1 + 0xa8);
            if (*(int *)(lParm1 + 0xa4) == iVar3) {
                *(undefined *)(lParm1 + 0xa0) = 1;
                return (ulong)local_24;
            }
        }
        iVar3 = (iVar4 - iVar1) + 1;
        if ((*(short *)(lVar2 + (long)iVar3 * 4) != *(short *)(lParm1 + 0xaa)) &&
                (*(short *)(*(long *)(lParm1 + 0x78) + (long)iVar3 * 2) == 0)) {
            *(int *)((long)(int)local_24 * 4 + lParm4) = iVar3;
            local_24 = local_24 + 1;
            *(undefined2 *)((long)iVar3 * 4 + lVar2) = *(undefined2 *)(lParm1 + 0xaa);
            *(undefined2 *)((long)iVar3 * 4 + lVar2 + 2) = *(undefined2 *)(lParm1 + 0xa8);
            if (*(int *)(lParm1 + 0xa4) == iVar3) {
                *(undefined *)(lParm1 + 0xa0) = 1;
                return (ulong)local_24;
            }
        }
        iVar3 = iVar4 + -1;
        if ((*(short *)(lVar2 + (long)iVar3 * 4) != *(short *)(lParm1 + 0xaa)) &&
                (*(short *)(*(long *)(lParm1 + 0x78) + (long)iVar3 * 2) == 0)) {
            *(int *)((long)(int)local_24 * 4 + lParm4) = iVar3;
            local_24 = local_24 + 1;
            *(undefined2 *)((long)iVar3 * 4 + lVar2) = *(undefined2 *)(lParm1 + 0xaa);
            *(undefined2 *)((long)iVar3 * 4 + lVar2 + 2) = *(undefined2 *)(lParm1 + 0xa8);
            if (*(int *)(lParm1 + 0xa4) == iVar3) {
                *(undefined *)(lParm1 + 0xa0) = 1;
                return (ulong)local_24;
            }
        }
        iVar3 = iVar4 + 1;
        if ((*(short *)(lVar2 + (long)iVar3 * 4) != *(short *)(lParm1 + 0xaa)) &&
                (*(short *)(*(long *)(lParm1 + 0x78) + (long)iVar3 * 2) == 0)) {
            *(int *)((long)(int)local_24 * 4 + lParm4) = iVar3;
            local_24 = local_24 + 1;
            *(undefined2 *)((long)iVar3 * 4 + lVar2) = *(undefined2 *)(lParm1 + 0xaa);
            *(undefined2 *)((long)iVar3 * 4 + lVar2 + 2) = *(undefined2 *)(lParm1 + 0xa8);
            if (*(int *)(lParm1 + 0xa4) == iVar3) {
                *(undefined *)(lParm1 + 0xa0) = 1;
                return (ulong)local_24;
            }
        }
        iVar3 = iVar1 + iVar4 + -1;
        if ((*(short *)(lVar2 + (long)iVar3 * 4) != *(short *)(lParm1 + 0xaa)) &&
                (*(short *)(*(long *)(lParm1 + 0x78) + (long)iVar3 * 2) == 0)) {
            *(int *)((long)(int)local_24 * 4 + lParm4) = iVar3;
            local_24 = local_24 + 1;
            *(undefined2 *)((long)iVar3 * 4 + lVar2) = *(undefined2 *)(lParm1 + 0xaa);
            *(undefined2 *)((long)iVar3 * 4 + lVar2 + 2) = *(undefined2 *)(lParm1 + 0xa8);
            if (*(int *)(lParm1 + 0xa4) == iVar3) {
                *(undefined *)(lParm1 + 0xa0) = 1;
                return (ulong)local_24;
            }
        }
        iVar3 = iVar1 + iVar4;
        if ((*(short *)(lVar2 + (long)iVar3 * 4) != *(short *)(lParm1 + 0xaa)) &&
                (*(short *)(*(long *)(lParm1 + 0x78) + (long)iVar3 * 2) == 0)) {
            *(int *)((long)(int)local_24 * 4 + lParm4) = iVar3;
            local_24 = local_24 + 1;
            *(undefined2 *)((long)iVar3 * 4 + lVar2) = *(undefined2 *)(lParm1 + 0xaa);
            *(undefined2 *)((long)iVar3 * 4 + lVar2 + 2) = *(undefined2 *)(lParm1 + 0xa8);
            if (*(int *)(lParm1 + 0xa4) == iVar3) {
                *(undefined *)(lParm1 + 0xa0) = 1;
                return (ulong)local_24;
            }
        }
        iVar4 = iVar1 + iVar4 + 1;
        if ((*(short *)(lVar2 + (long)iVar4 * 4) != *(short *)(lParm1 + 0xaa)) &&
                (*(short *)(*(long *)(lParm1 + 0x78) + (long)iVar4 * 2) == 0)) {
            *(int *)((long)(int)local_24 * 4 + lParm4) = iVar4;
            local_24 = local_24 + 1;
            *(undefined2 *)((long)iVar4 * 4 + lVar2) = *(undefined2 *)(lParm1 + 0xaa);
            *(undefined2 *)((long)iVar4 * 4 + lVar2 + 2) = *(undefined2 *)(lParm1 + 0xa8);
            if (*(int *)(lParm1 + 0xa4) == iVar4) {
                *(undefined *)(lParm1 + 0xa0) = 1;
                return (ulong)local_24;
            }
        }
        if (*(int *)(lParm1 + 0x98) <= (int)local_24) {
            local_24 = *(int *)(lParm1 + 0x98) - 1;
        }
        local_20 = local_20 + 1;
    } while( true );
}


void _ZN6regobj6createEii(long lParm1,int iParm2,int iParm3)

{
    long *plVar1;
    bool local_21;
    uint local_20;
    uint local_1c;
    uint local_18;
    uint local_14;
    int local_10;
    int local_c;

    *(int *)(lParm1 + 0x14) = iParm2;
    *(int *)(lParm1 + 0x18) = iParm3;
    *(undefined4 *)(lParm1 + 0x10) = 0;
    _ZN9flexarrayI6pointtE6createEi(_ZN6regobj9bound1arpE,0x80);
    _ZN9flexarrayI6pointtE6createEi(_ZN6regobj9bound2arpE,0x80);
    _ZN9flexarrayIP6regobjE6createEi(lParm1 + 0x28,4);
    local_18 = iParm2 - 1;
    local_14 = iParm3 - 1;
    local_10 = iParm2 + 1;
    local_c = iParm3 + 1;
    if ((int)local_18 < 0) {
        local_18 = 0;
    }
    if ((int)local_14 < 0) {
        local_14 = 0;
    }
    if (*(int *)(*(long *)(lParm1 + 8) + 0x13c) < local_10) {
        local_10 = *(int *)(*(long *)(lParm1 + 8) + 0x13c);
    }
    if (*(int *)(*(long *)(lParm1 + 8) + 0x140) < local_c) {
        local_c = *(int *)(*(long *)(lParm1 + 8) + 0x140);
    }
    local_1c = local_14;
    while ((int)local_1c <= local_c) {
        local_20 = local_18;
        while ((int)local_20 <= local_10) {
            plVar1 = (long *)_ZN9regmngobj7regmappEii
                (*(undefined8 *)(lParm1 + 8),(ulong)local_20,(ulong)local_1c,
                 (ulong)local_20);
            if (*plVar1 == 0) {
                _ZN6regobj10addtoboundER9flexarrayI6pointtEii(lParm1,_ZN6regobj9bound1arpE,(ulong)local_20);
            }
            local_20 = local_20 + 1;
        }
        local_1c = local_1c + 1;
    }
    _ZN6regobj6boundlE = _ZN6regobj9bound1arpE._8_4_;
    if (_ZN6regobj9bound1arpE._8_4_ == 0) {
        *(undefined *)(lParm1 + 4) = 0;
        _ZN9flexarrayI6pointtE7destroyEv(_ZN6regobj9bound1arpE);
        _ZN9flexarrayI6pointtE7destroyEv(_ZN6regobj9bound2arpE);
    }
    else {
        *(undefined *)(lParm1 + 4) = 1;
        _ZN6regobj5floddE = '\0';
        while (_ZN6regobj6boundlE != 0) {
            local_21 = _ZN6regobj5floddE == '\x01';
            if (local_21) {
                _ZN6regobj10makebound2ER9flexarrayI6pointtES3_
                    (lParm1,_ZN6regobj9bound2arpE,_ZN6regobj9bound1arpE);
                _ZN6regobj6boundlE = _ZN6regobj9bound1arpE._8_4_;
            }
            else {
                _ZN6regobj10makebound2ER9flexarrayI6pointtES3_
                    (lParm1,_ZN6regobj9bound1arpE,_ZN6regobj9bound2arpE);
                _ZN6regobj6boundlE = _ZN6regobj9bound2arpE._8_4_;
            }
            local_21 = !local_21;
            _ZN6regobj5floddE = local_21;
        }
        _ZN9flexarrayI6pointtE7destroyEv(_ZN6regobj9bound1arpE);
        _ZN9flexarrayI6pointtE7destroyEv(_ZN6regobj9bound2arpE);
    }
    return;
}



ulong _ZN9regmngobj17foundemptyregionsEv(long lParm1)

{
    long *plVar1;
    uint local_c;

    local_c = 0;
    while ((int)local_c < (int)*(uint *)(lParm1 + 0x188)) {
        plVar1 = (long *)_ZN15largesolidarrayIP6regobjEixEi
            (lParm1 + 0x150,(ulong)local_c,lParm1 + 0x150);
        if (*(int *)(*plVar1 + 0x10) == 0) {
            plVar1 = (long *)_ZN15largesolidarrayIP6regobjEixEi
                (lParm1 + 0x150,(ulong)local_c,lParm1 + 0x150);
            *(undefined *)(*plVar1 + 4) = 0;
        }
        local_c = local_c + 1;
    }
    return (ulong)*(uint *)(lParm1 + 0x188);
}



undefined8
    _ZN6wayobj9createwayEiiiiRP8point16tRi
(long param_1,uint param_2,uint param_3,uint param_4,uint param_5,void **param_6,
 undefined4 *param_7)

{
    uint uVar1;
    bool bVar2;
    char cVar3;
    uint uVar4;
    undefined8 uVar5;
    short *psVar6;
    void *pvVar7;

    cVar3 = _ZN6wayobj5ismapEii(param_1,(ulong)param_2,(ulong)param_3,(ulong)param_2);
    if (cVar3 == '\x01') {
        cVar3 = _ZN6wayobj5ismapEii(param_1,(ulong)param_4,(ulong)param_5,(ulong)param_4);
        if (cVar3 == '\x01') {
            bVar2 = false;
            goto LAB_00402b52;
        }
    }
    bVar2 = true;
LAB_00402b52:
    if (bVar2) {
        *param_6 = (void *)0x0;
        *param_7 = 0;
        uVar5 = 0;
    }
    else {
        psVar6 = (short *)_ZN6wayobj3mapEii(param_1,(ulong)param_4,(ulong)param_5,(ulong)param_4);
        if (*psVar6 == 0) {
            if ((param_2 == param_4) && (param_3 == param_5)) {
                pvVar7 = malloc(4);
                *param_6 = pvVar7;
                *param_7 = 1;
                uVar5 = 1;
            }
            else {
                cVar3 = _ZN6wayobj4fillEiiii
                    (param_1,(ulong)param_2,(ulong)param_3,(ulong)param_4,(ulong)param_5);
                if (cVar3 == '\x01') {
                    uVar1 = *(uint *)(param_1 + 0xa4);
                    uVar4 = _ZN6wayobj5indexEii(param_1,(ulong)param_2,(ulong)param_3,(ulong)param_2);
                    cVar3 = _ZN6wayobj11createwayarEiiRP8point16tRi
                        (param_1,(ulong)uVar4,(ulong)uVar1,param_6,param_7);
                    if (cVar3 == '\x01') {
                        uVar5 = 1;
                    }
                    else {
                        *param_6 = (void *)0x0;
                        *param_7 = 0;
                        uVar5 = 0;
                    }
                }
                else {
                    *param_6 = (void *)0x0;
                    *param_7 = 0;
                    uVar5 = 0;
                }
            }
        }
        else {
            *param_6 = (void *)0x0;
            *param_7 = 0;
            uVar5 = 0;
        }
    }
    return uVar5;
}


void _ZN7way2obj12releaseboundEv(long lParm1)

{
    uint uVar1;
    long lVar2;
    uint *puVar3;
    uint local_1c;

    if (*(int *)(lParm1 + ((long)*(int *)(lParm1 + 0x1118) + 0x11) * 0x10 + 0x10) == 0) {
        *(int *)(lParm1 + 0x111c) = *(int *)(lParm1 + 0x111c) + 1;
    }
    else {
        *(undefined4 *)(lParm1 + 0x111c) = 0;
        local_1c = *(uint *)(lParm1 + ((long)*(int *)(lParm1 + 0x1118) + 0x11) * 0x10 + 0x10);
        while (local_1c = local_1c - 1, -1 < (int)local_1c) {
            lVar2 = lParm1 + ((long)*(int *)(lParm1 + 0x1118) + 0x11) * 0x10 + 8;
            lVar2 = _ZN9flexarrayI6pointtEixEi(lVar2,(ulong)local_1c,lVar2);
            uVar1 = *(uint *)(lVar2 + 4);
            lVar2 = lParm1 + ((long)*(int *)(lParm1 + 0x1118) + 0x11) * 0x10 + 8;
            puVar3 = (uint *)_ZN9flexarrayI6pointtEixEi(lVar2,(ulong)local_1c,lVar2);
            _ZN7way2obj12releasepointEii(lParm1,(ulong)*puVar3,(ulong)uVar1);
        }
        _ZN9flexarrayI6pointtE5clearEv(lParm1 + ((long)*(int *)(lParm1 + 0x1118) + 0x11) * 0x10 + 8);
    }
    return;
}


ulong _ZN9regmngobj13addallregionsEv(long lParm1)

{
    byte bVar1;
    long *plVar2;
    uint local_10;
    uint local_c;

    local_c = 0;
    while ((int)local_c <= (int)*(uint *)(lParm1 + 0x140)) {
        local_10 = 0;
        while ((int)local_10 <= *(int *)(lParm1 + 0x13c)) {
            plVar2 = (long *)_ZN9regmngobj7regmappEii
                (lParm1,(ulong)local_10,(ulong)local_c,(ulong)local_10);
            if (*plVar2 == 0) {
                bVar1 = _ZN9regmngobj4mappEii(lParm1,(ulong)local_10,(ulong)local_c);
                if (*(char *)(lParm1 + 0x30 + (long)(int)(uint)bVar1) != '\0') {
                    _ZN9regmngobj9newregionEii(lParm1,(ulong)local_10,(ulong)local_c);
                }
            }
            local_10 = local_10 + 1;
        }
        local_c = local_c + 1;
    }
    return (ulong)*(uint *)(lParm1 + 0x140);
}


ulong _ZN7way2obj4fillEii(long lParm1,uint uParm2,uint uParm3)

{
    uint uVar1;
    long in_FS_OFFSET;
    int local_1c;
    undefined local_18 [8];
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    local_1c = 0;
    while (local_1c < 0x100) {
        _ZN9flexarrayI6pointtE5clearEv(lParm1 + ((long)local_1c + 0x11) * 0x10 + 8);
        local_1c = local_1c + 1;
    }
    *(short *)(lParm1 + 0x10) = *(short *)(lParm1 + 0x10) + 1;
    if (*(short *)(lParm1 + 0x10) == -1) {
        memset(*(void **)(lParm1 + 8),0,
                (long)(*(int *)(lParm1 + 0x1144) * *(int *)(lParm1 + 0x1140)) * 4);
        *(undefined2 *)(lParm1 + 0x10) = 1;
    }
    *(undefined *)(lParm1 + 0x1134) = 0;
    *(undefined4 *)(lParm1 + 0x111c) = 0;
    _ZN6pointtC2Eii(local_18,(ulong)uParm2,(ulong)uParm3);
    _ZN9flexarrayI6pointtE3addERKS0_(lParm1 + 0x118,local_18,lParm1 + 0x118);
    *(undefined2 *)
        ((long)(int)(uParm2 + *(int *)(lParm1 + 0x1140) * uParm3) * 4 + *(long *)(lParm1 + 8) + 2) = 0;
    *(undefined4 *)(lParm1 + 0x1118) = 0;
    *(undefined4 *)(lParm1 + 0x1120) = 0;
    while ((*(char *)(lParm1 + 0x1134) == '\0' && (*(int *)(lParm1 + 0x111c) < 0x109))) {
        uVar1 = (uint)(*(int *)(lParm1 + 0x1120) >> 0x1f) >> 0x18;
        *(int *)(lParm1 + 0x1118) = (*(int *)(lParm1 + 0x1120) + uVar1 & 0xff) - uVar1;
        _ZN7way2obj12releaseboundEv(lParm1);
        *(int *)(lParm1 + 0x1120) = *(int *)(lParm1 + 0x1120) + 1;
    }
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
    }
    return (ulong)*(byte *)(lParm1 + 0x1134);
}



undefined8 _ZN9regmngobj7loadmapEPKc(void **ppvParm1,char *pcParm2)

{
  int __fd;
  undefined8 uVar1;
  void *pvVar2;
  int local_10;
  
  __fd = open(pcParm2,0);
  if (__fd == -1) {
    uVar1 = 0;
  }
  else {
    read(__fd,(void *)((long)ppvParm1 + 0x144),4);
    read(__fd,ppvParm1 + 0x29,4);
    *(int *)((long)ppvParm1 + 0x13c) = *(int *)((long)ppvParm1 + 0x144) + -1;
    *(int *)(ppvParm1 + 0x28) = *(int *)(ppvParm1 + 0x29) + -1;
    pvVar2 = malloc((long)(*(int *)(ppvParm1 + 0x29) * *(int *)((long)ppvParm1 + 0x144)) << 3);
    ppvParm1[4] = pvVar2;
    pvVar2 = malloc((long)(*(int *)(ppvParm1 + 0x29) * *(int *)((long)ppvParm1 + 0x144)));
    ppvParm1[5] = pvVar2;
    pvVar2 = malloc((long)(*(int *)(ppvParm1 + 0x29) * *(int *)((long)ppvParm1 + 0x144)) * 2);
    *ppvParm1 = pvVar2;
    memset(*ppvParm1,0,(long)(*(int *)(ppvParm1 + 0x29) * *(int *)((long)ppvParm1 + 0x144)) * 2);
    *(undefined2 *)(ppvParm1 + 1) = 0;
    read(__fd,ppvParm1[5],(long)(*(int *)(ppvParm1 + 0x29) * *(int *)((long)ppvParm1 + 0x144)));
    local_10 = 0;
    while (local_10 < 0x100) {
      *(undefined *)((long)ppvParm1 + (long)local_10 + 0x30) = 0;
      local_10 = local_10 + 1;
    }
    *(undefined *)(ppvParm1 + 6) = 1;
    close(__fd);
    uVar1 = 1;
  }
  return uVar1;
}




void _ZN9regmngobj13defineregionsEv(long lParm1)

{
  bool bVar1;
  char cVar2;
  undefined4 uVar3;
  long *plVar4;
  undefined4 *puVar5;
  undefined8 uVar6;
  long in_FS_OFFSET;
  double dVar7;
  double dVar8;
  uint local_74;
  uint local_70;
  uint local_6c;
  uint local_68;
  int local_64;
  uint local_60;
  int local_5c;
  int local_58;
  uint local_54;
  uint local_50;
  uint local_4c;
  undefined4 *local_48;
  long local_40;
  undefined local_38 [8];
  int local_30;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  _ZN9flexarrayI11regboundobjE6createEi(local_38,0x10);
  dVar7 = round((double)((((float)*(int *)(lParm1 + 0x13c) / 620.00000000) * 34.00000000) /
                        *(float *)(lParm1 + 0x138)));
  local_5c = (int)dVar7;
  dVar7 = round((double)((((float)*(int *)(lParm1 + 0x140) / 309.00000000) * 20.00000000) /
                        *(float *)(lParm1 + 0x138)));
  local_58 = (int)dVar7;
  dVar7 = round((double)((float)(*(int *)(lParm1 + 0x13c) + 1) / (float)local_5c));
  local_54 = (uint)dVar7;
  dVar7 = round(((double)((float)(*(int *)(lParm1 + 0x140) + 1) / (float)local_58) * 1.73205081) /
                2.00000000);
  local_50 = (uint)dVar7;
  local_64 = 0;
  local_60 = 0;
  do {
    if ((local_60 & 1) == 0) {
      local_68 = local_64 * local_54 + ((int)(local_54 + (local_54 >> 0x1f)) >> 1);
    }
    else {
      local_68 = (local_64 + 1) * local_54;
    }
    local_4c = local_60 * local_50 + ((int)(local_50 + (local_50 >> 0x1f)) >> 1);
    cVar2 = _ZN9regmngobj13findfreeplaceEiiRiS0_
                      (lParm1,(ulong)local_68,(ulong)local_4c,&local_74,&local_70);
    if ((cVar2 == '\x01') &&
       (plVar4 = (long *)_ZN9regmngobj7regmappEii(lParm1,(ulong)local_74,(ulong)local_70),
       *plVar4 == 0)) {
      puVar5 = (undefined4 *)_Znwm(0x38);
      _ZN6regobjC2EP9regmngobj(puVar5,lParm1);
      local_48 = puVar5;
      uVar3 = _ZN15largesolidarrayIP6regobjE3addERKS1_(lParm1 + 0x150,&local_48,lParm1 + 0x150);
      *puVar5 = uVar3;
      _ZN6regobj6createEv(local_48);
      *(undefined *)(local_48 + 1) = 1;
      local_48[5] = local_74;
      local_48[6] = local_70;
      local_40 = _ZN9flexarrayI11regboundobjE3addEv(local_38);
      *(undefined *)(local_40 + 0x68) = 1;
      _ZN11regboundobj9firststepEiiP6regobjP9regmngobj
                (local_40,(ulong)local_74,(ulong)local_70,local_48,lParm1);
    }
    local_64 = local_64 + 1;
    if ((local_60 & 1) == 0) {
      if (local_64 == local_5c) {
        local_64 = 0;
        local_60 = local_60 + 1;
      }
    }
    else {
      if (local_5c + -1 == local_64) {
        local_64 = 0;
        local_60 = local_60 + 1;
      }
    }
    dVar8 = (double)local_60;
    dVar7 = round((double)((float)local_58 + (float)local_58) / 1.73205081);
  } while (dVar8 < dVar7 + 3.00000000);
  do {
    bVar1 = true;
    local_6c = 0;
    while ((int)local_6c < local_30) {
      uVar6 = _ZN9flexarrayI11regboundobjEixEi(local_38,(ulong)local_6c);
      cVar2 = _ZN11regboundobj4stepEv(uVar6);
      if (cVar2 != '\0') {
        bVar1 = false;
      }
      local_6c = local_6c + 1;
    }
  } while (!bVar1);
  local_6c = 0;
  while ((int)local_6c < local_30) {
    uVar6 = _ZN9flexarrayI11regboundobjEixEi(local_38,(ulong)local_6c,(ulong)local_6c);
    _ZN11regboundobj7destroyEv(uVar6);
    local_6c = local_6c + 1;
  }
  _ZN9flexarrayI11regboundobjE7destroyEv(local_38);
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


