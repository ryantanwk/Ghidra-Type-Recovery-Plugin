void storeValue(FILE *pFParm1,void *pvParm2)

{
    long lVar1;
    long in_FS_OFFSET;

    lVar1 = *(long *)(in_FS_OFFSET + 0x28);
    fwrite(pvParm2,4,1,pFParm1);
    if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
        return;
    }
    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
}

void loadValue(FILE *pFParm1,void *pvParm2)

{
    long lVar1;
    long in_FS_OFFSET;

    lVar1 = *(long *)(in_FS_OFFSET + 0x28);
    fread(pvParm2,4,1,pFParm1);
    if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
        return;
    }
    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
}

void MAIN_initialize(long lParm1)

{
    LBM_allocateGrid(&srcGrid);
    LBM_allocateGrid(&dstGrid);
    LBM_initializeGrid(srcGrid);
    LBM_initializeGrid(dstGrid);
    if (*(long *)(lParm1 + 0x18) != 0) {
        LBM_loadObstacleFile(srcGrid,*(undefined8 *)(lParm1 + 0x18),*(undefined8 *)(lParm1 + 0x18));
        LBM_loadObstacleFile(dstGrid,*(undefined8 *)(lParm1 + 0x18),*(undefined8 *)(lParm1 + 0x18));
    }
    if (*(int *)(lParm1 + 0x14) == 1) {
        LBM_initializeSpecialCellsForChannel(srcGrid);
        LBM_initializeSpecialCellsForChannel(dstGrid);
    }
    else {
        LBM_initializeSpecialCellsForLDC(srcGrid);
        LBM_initializeSpecialCellsForLDC(dstGrid);
    }
    LBM_showGridStatistics(srcGrid);
    return;
}


void LBM_storeVelocityField(long lParm1,char *pcParm2,int iParm3)

{
    char *__modes;
    long in_FS_OFFSET;
    float local_34;
    float local_30;
    float local_2c;
    int local_28;
    int local_24;
    int local_20;
    float local_1c;
    FILE *local_18;
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    if (iParm3 == 0) {
        __modes = "w";
    }
    else {
        __modes = "wb";
    }
    local_18 = fopen(pcParm2,__modes);
    local_20 = 0;
    while (local_20 < 0x82) {
        local_24 = 0;
        while (local_24 < 100) {
            local_28 = 0;
            while (local_28 < 100) {
                local_1c = (float)(*(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         8) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x10) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x18) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x20) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x28) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x30) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x38) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x40) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x48) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x50) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x58) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x60) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x68) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x70) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x78) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x80) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x88) +
                        *(double *)
                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                         0x90));
                local_34 = (float)((((((((*(double *)
                                                    (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                                     0xa0 + 0x18) -
                                                    *(double *)
                                                    (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                                     0xa0 + 0x20)) +
                                                *(double *)
                                                (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                                 0xa0 + 0x38)) -
                                            *(double *)
                                            (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                             0xa0 + 0x40)) +
                                        *(double *)
                                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0
                                         + 0x48)) -
                                    *(double *)
                                    (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0
                                     + 0x50)) +
                                *(double *)
                                (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0
                                 + 0x78) +
                                *(double *)
                                (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                                 0x80)) -
                                 *(double *)
                                 (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                                  0x88)) -
                                  *(double *)
                                  (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                                   0x90)) / local_1c;
                local_30 = (float)(((((((*(double *)
                                                (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                                 0xa0 + 8) -
                                                *(double *)
                                                (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                                 0xa0 + 0x10)) +
                                            *(double *)
                                            (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                             0xa0 + 0x38) +
                                            *(double *)
                                            (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                             0xa0 + 0x40)) -
                                        *(double *)
                                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0
                                         + 0x48)) -
                                    *(double *)
                                    (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0
                                     + 0x50)) +
                                *(double *)
                                (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0
                                 + 0x58) +
                                *(double *)
                                (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                                 0x60)) -
                                 *(double *)
                                 (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                                  0x68)) -
                                  *(double *)
                                  (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                                   0x70)) / local_1c;
                local_2c = (float)(((((((((*(double *)
                                                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                                         0xa0 + 0x28) -
                                                        *(double *)
                                                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                                         0xa0 + 0x30)) +
                                                    *(double *)
                                                    (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                                     0xa0 + 0x58)) -
                                                *(double *)
                                                (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                                 0xa0 + 0x60)) +
                                            *(double *)
                                            (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) *
                                             0xa0 + 0x68)) -
                                        *(double *)
                                        (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0
                                         + 0x70)) +
                                    *(double *)
                                    (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0
                                     + 0x78)) -
                                     *(double *)
                                     (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                                      0x80)) +
                                      *(double *)
                                      (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                                       0x88)) -
                                       *(double *)
                                       (lParm1 + (long)(local_20 * 10000 + local_24 * 100 + local_28) * 0xa0 +
                                        0x90)) / local_1c;
                if (iParm3 == 0) {
                    fprintf((FILE *)(double)local_34,(char *)(double)local_30,(double)local_2c,local_18,
                            "%e %e %e\n");
                }
                else {
                    storeValue(local_18,&local_34,&local_34);
                    storeValue(local_18,&local_30,&local_30);
                    storeValue(local_18,&local_2c,&local_2c);
                }
                local_28 = local_28 + 1;
            }
            local_24 = local_24 + 1;
        }
        local_20 = local_20 + 1;
    }
    fclose(local_18);
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
    }
    return;
}

void LBM_handleInOutFlow(long lParm1)

{
    double dVar1;
    double dVar2;
    double dVar3;
    double dVar4;
    int local_84;

    local_84 = 0;
    while (local_84 < 200000) {
        dVar2 = *(double *)(lParm1 + (long)(local_84 + 0x30d41) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 200000) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d42) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d43) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d44) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d45) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d46) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d47) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d48) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d49) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d4a) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d4b) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d4c) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d4d) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d4e) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d4f) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d50) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d51) * 8) +
            *(double *)(lParm1 + (long)(local_84 + 0x30d52) * 8);
        dVar2 = (dVar2 + dVar2) -
            (*(double *)(lParm1 + (long)(local_84 + 0x61a81) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 400000) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a82) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a83) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a84) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a85) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a86) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a87) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a88) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a89) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a8a) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a8b) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a8c) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a8d) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a8e) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a8f) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a90) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a91) * 8) +
             *(double *)(lParm1 + (long)(local_84 + 0x61a92) * 8));
        dVar3 = (double)((local_84 / 0x14) % 100) / 49.50000000 - 1.00000000;
        dVar1 = (double)((local_84 / 2000) % 100) / 49.50000000 - 1.00000000;
        dVar3 = (1.00000000 - dVar1 * dVar1) * (1.00000000 - dVar3 * dVar3) * 0.01000000;
        dVar1 = (dVar3 * dVar3 + 0.00000000) * 1.50000000;
        *(double *)(lParm1 + (long)local_84 * 8) = (1.00000000 - dVar1) * dVar2 * 0.33333333;
        *(double *)(lParm1 + (long)(local_84 + 1) * 8) = (1.00000000 - dVar1) * dVar2 * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 2) * 8) = (1.00000000 - dVar1) * dVar2 * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 3) * 8) = (1.00000000 - dVar1) * dVar2 * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 4) * 8) = (1.00000000 - dVar1) * dVar2 * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 5) * 8) =
            (((dVar3 * 4.50000000 + 3.00000000) * dVar3 + 1.00000000) - dVar1) * dVar2 * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 6) * 8) =
            (((dVar3 * 4.50000000 - 3.00000000) * dVar3 + 1.00000000) - dVar1) * dVar2 * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 7) * 8) = (1.00000000 - dVar1) * dVar2 * 0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 8) * 8) = (1.00000000 - dVar1) * dVar2 * 0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 9) * 8) = (1.00000000 - dVar1) * dVar2 * 0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 10) * 8) = (1.00000000 - dVar1) * dVar2 * 0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0xb) * 8) =
            ((((dVar3 + 0.00000000) * 4.50000000 + 3.00000000) * (dVar3 + 0.00000000) + 1.00000000) -
             dVar1) * dVar2 * 0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0xc) * 8) =
            ((((0.00000000 - dVar3) * 4.50000000 + 3.00000000) * (0.00000000 - dVar3) + 1.00000000) -
             dVar1) * dVar2 * 0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0xd) * 8) =
            ((((dVar3 - 0.00000000) * 4.50000000 + 3.00000000) * (dVar3 - 0.00000000) + 1.00000000) -
             dVar1) * dVar2 * 0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0xe) * 8) =
            ((((-0.00000000 - dVar3) * 4.50000000 + 3.00000000) * (-0.00000000 - dVar3) + 1.00000000) -
             dVar1) * dVar2 * 0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0xf) * 8) =
            ((((dVar3 + 0.00000000) * 4.50000000 + 3.00000000) * (dVar3 + 0.00000000) + 1.00000000) -
             dVar1) * dVar2 * 0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0x10) * 8) =
            ((((0.00000000 - dVar3) * 4.50000000 + 3.00000000) * (0.00000000 - dVar3) + 1.00000000) -
             dVar1) * dVar2 * 0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0x11) * 8) =
            ((((dVar3 - 0.00000000) * 4.50000000 + 3.00000000) * (dVar3 - 0.00000000) + 1.00000000) -
             dVar1) * dVar2 * 0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0x12) * 8) =
            ((((-0.00000000 - dVar3) * 4.50000000 + 3.00000000) * (-0.00000000 - dVar3) + 1.00000000) -
             dVar1) * dVar2 * 0.02777778;
        local_84 = local_84 + 0x14;
    }
    local_84 = 25800000;
    while (local_84 < 26000000) {
        dVar1 = *(double *)(lParm1 + (long)(local_84 + -199999) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -200000) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d3e) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d3d) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d3c) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d3b) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d3a) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d39) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d38) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d37) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d36) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d35) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d34) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d33) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d32) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d31) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d30) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d2f) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x30d2e) * 8);
        dVar2 = ((((((((*(double *)(lParm1 + (long)(local_84 + -0x30d3d) * 8) -
                                            *(double *)(lParm1 + (long)(local_84 + -0x30d3c) * 8)) +
                                        *(double *)(lParm1 + (long)(local_84 + -0x30d39) * 8)) -
                                    *(double *)(lParm1 + (long)(local_84 + -0x30d38) * 8)) +
                                *(double *)(lParm1 + (long)(local_84 + -0x30d37) * 8)) -
                            *(double *)(lParm1 + (long)(local_84 + -0x30d36) * 8)) +
                        *(double *)(lParm1 + (long)(local_84 + -0x30d31) * 8) +
                        *(double *)(lParm1 + (long)(local_84 + -0x30d30) * 8)) -
                    *(double *)(lParm1 + (long)(local_84 + -0x30d2f) * 8)) -
                *(double *)(lParm1 + (long)(local_84 + -0x30d2e) * 8)) / dVar1;
        dVar3 = (((((((*(double *)(lParm1 + (long)(local_84 + -199999) * 8) -
                                        *(double *)(lParm1 + (long)(local_84 + -0x30d3e) * 8)) +
                                    *(double *)(lParm1 + (long)(local_84 + -0x30d39) * 8) +
                                    *(double *)(lParm1 + (long)(local_84 + -0x30d38) * 8)) -
                                *(double *)(lParm1 + (long)(local_84 + -0x30d37) * 8)) -
                            *(double *)(lParm1 + (long)(local_84 + -0x30d36) * 8)) +
                        *(double *)(lParm1 + (long)(local_84 + -0x30d35) * 8) +
                        *(double *)(lParm1 + (long)(local_84 + -0x30d34) * 8)) -
                    *(double *)(lParm1 + (long)(local_84 + -0x30d33) * 8)) -
                *(double *)(lParm1 + (long)(local_84 + -0x30d32) * 8)) / dVar1;
        dVar1 = (((((((((*(double *)(lParm1 + (long)(local_84 + -0x30d3b) * 8) -
                                                *(double *)(lParm1 + (long)(local_84 + -0x30d3a) * 8)) +
                                            *(double *)(lParm1 + (long)(local_84 + -0x30d35) * 8)) -
                                        *(double *)(lParm1 + (long)(local_84 + -0x30d34) * 8)) +
                                    *(double *)(lParm1 + (long)(local_84 + -0x30d33) * 8)) -
                                *(double *)(lParm1 + (long)(local_84 + -0x30d32) * 8)) +
                            *(double *)(lParm1 + (long)(local_84 + -0x30d31) * 8)) -
                        *(double *)(lParm1 + (long)(local_84 + -0x30d30) * 8)) +
                    *(double *)(lParm1 + (long)(local_84 + -0x30d2f) * 8)) -
                *(double *)(lParm1 + (long)(local_84 + -0x30d2e) * 8)) / dVar1;
        dVar4 = *(double *)(lParm1 + (long)(local_84 + -399999) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -400000) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a7e) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a7d) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a7c) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a7b) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a7a) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a79) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a78) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a77) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a76) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a75) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a74) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a73) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a72) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a71) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a70) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a6f) * 8) +
            *(double *)(lParm1 + (long)(local_84 + -0x61a6e) * 8);
        dVar2 = (dVar2 + dVar2) -
            ((((((((*(double *)(lParm1 + (long)(local_84 + -0x61a7d) * 8) -
                    *(double *)(lParm1 + (long)(local_84 + -0x61a7c) * 8)) +
                   *(double *)(lParm1 + (long)(local_84 + -0x61a79) * 8)) -
                  *(double *)(lParm1 + (long)(local_84 + -0x61a78) * 8)) +
                 *(double *)(lParm1 + (long)(local_84 + -0x61a77) * 8)) -
                *(double *)(lParm1 + (long)(local_84 + -0x61a76) * 8)) +
               *(double *)(lParm1 + (long)(local_84 + -0x61a71) * 8) +
               *(double *)(lParm1 + (long)(local_84 + -0x61a70) * 8)) -
              *(double *)(lParm1 + (long)(local_84 + -0x61a6f) * 8)) -
             *(double *)(lParm1 + (long)(local_84 + -0x61a6e) * 8)) / dVar4;
        dVar3 = (dVar3 + dVar3) -
            (((((((*(double *)(lParm1 + (long)(local_84 + -399999) * 8) -
                   *(double *)(lParm1 + (long)(local_84 + -0x61a7e) * 8)) +
                  *(double *)(lParm1 + (long)(local_84 + -0x61a79) * 8) +
                  *(double *)(lParm1 + (long)(local_84 + -0x61a78) * 8)) -
                 *(double *)(lParm1 + (long)(local_84 + -0x61a77) * 8)) -
                *(double *)(lParm1 + (long)(local_84 + -0x61a76) * 8)) +
               *(double *)(lParm1 + (long)(local_84 + -0x61a75) * 8) +
               *(double *)(lParm1 + (long)(local_84 + -0x61a74) * 8)) -
              *(double *)(lParm1 + (long)(local_84 + -0x61a73) * 8)) -
             *(double *)(lParm1 + (long)(local_84 + -0x61a72) * 8)) / dVar4;
        dVar1 = (dVar1 + dVar1) -
            (((((((((*(double *)(lParm1 + (long)(local_84 + -0x61a7b) * 8) -
                     *(double *)(lParm1 + (long)(local_84 + -0x61a7a) * 8)) +
                    *(double *)(lParm1 + (long)(local_84 + -0x61a75) * 8)) -
                   *(double *)(lParm1 + (long)(local_84 + -0x61a74) * 8)) +
                  *(double *)(lParm1 + (long)(local_84 + -0x61a73) * 8)) -
                 *(double *)(lParm1 + (long)(local_84 + -0x61a72) * 8)) +
                *(double *)(lParm1 + (long)(local_84 + -0x61a71) * 8)) -
               *(double *)(lParm1 + (long)(local_84 + -0x61a70) * 8)) +
              *(double *)(lParm1 + (long)(local_84 + -0x61a6f) * 8)) -
             *(double *)(lParm1 + (long)(local_84 + -0x61a6e) * 8)) / dVar4;
        dVar4 = (dVar1 * dVar1 + dVar2 * dVar2 + dVar3 * dVar3) * 1.50000000;
        *(double *)(lParm1 + (long)local_84 * 8) = (1.00000000 - dVar4) * 0.33333333;
        *(double *)(lParm1 + (long)(local_84 + 1) * 8) =
            (((dVar3 * 4.50000000 + 3.00000000) * dVar3 + 1.00000000) - dVar4) * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 2) * 8) =
            (((dVar3 * 4.50000000 - 3.00000000) * dVar3 + 1.00000000) - dVar4) * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 3) * 8) =
            (((dVar2 * 4.50000000 + 3.00000000) * dVar2 + 1.00000000) - dVar4) * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 4) * 8) =
            (((dVar2 * 4.50000000 - 3.00000000) * dVar2 + 1.00000000) - dVar4) * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 5) * 8) =
            (((dVar1 * 4.50000000 + 3.00000000) * dVar1 + 1.00000000) - dVar4) * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 6) * 8) =
            (((dVar1 * 4.50000000 - 3.00000000) * dVar1 + 1.00000000) - dVar4) * 0.05555556;
        *(double *)(lParm1 + (long)(local_84 + 7) * 8) =
            ((((dVar2 + dVar3) * 4.50000000 + 3.00000000) * (dVar2 + dVar3) + 1.00000000) - dVar4) *
            0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 8) * 8) =
            ((((dVar3 - dVar2) * 4.50000000 + 3.00000000) * (dVar3 - dVar2) + 1.00000000) - dVar4) *
            0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 9) * 8) =
            ((((dVar2 - dVar3) * 4.50000000 + 3.00000000) * (dVar2 - dVar3) + 1.00000000) - dVar4) *
            0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 10) * 8) =
            (((((double)((ulong)dVar2 ^ 0x8000000000000000) - dVar3) * 4.50000000 + 3.00000000) *
              ((double)((ulong)dVar2 ^ 0x8000000000000000) - dVar3) + 1.00000000) - dVar4) * 0.02777778
            ;
        *(double *)(lParm1 + (long)(local_84 + 0xb) * 8) =
            ((((dVar3 + dVar1) * 4.50000000 + 3.00000000) * (dVar3 + dVar1) + 1.00000000) - dVar4) *
            0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0xc) * 8) =
            ((((dVar3 - dVar1) * 4.50000000 + 3.00000000) * (dVar3 - dVar1) + 1.00000000) - dVar4) *
            0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0xd) * 8) =
            ((((dVar1 - dVar3) * 4.50000000 + 3.00000000) * (dVar1 - dVar3) + 1.00000000) - dVar4) *
            0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0xe) * 8) =
            (((((double)((ulong)dVar3 ^ 0x8000000000000000) - dVar1) * 4.50000000 + 3.00000000) *
              ((double)((ulong)dVar3 ^ 0x8000000000000000) - dVar1) + 1.00000000) - dVar4) * 0.02777778
            ;
        *(double *)(lParm1 + (long)(local_84 + 0xf) * 8) =
            ((((dVar2 + dVar1) * 4.50000000 + 3.00000000) * (dVar2 + dVar1) + 1.00000000) - dVar4) *
            0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0x10) * 8) =
            ((((dVar2 - dVar1) * 4.50000000 + 3.00000000) * (dVar2 - dVar1) + 1.00000000) - dVar4) *
            0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0x11) * 8) =
            ((((dVar1 - dVar2) * 4.50000000 + 3.00000000) * (dVar1 - dVar2) + 1.00000000) - dVar4) *
            0.02777778;
        *(double *)(lParm1 + (long)(local_84 + 0x12) * 8) =
            (((((double)((ulong)dVar2 ^ 0x8000000000000000) - dVar1) * 4.50000000 + 3.00000000) *
              ((double)((ulong)dVar2 ^ 0x8000000000000000) - dVar1) + 1.00000000) - dVar4) * 0.02777778
            ;
        local_84 = local_84 + 0x14;
    }
    return;
}

void LBM_initializeGrid(long lParm1)

{
    int local_14;

    local_14 = -400000;
    while (local_14 < 26400000) {
        *(undefined8 *)(lParm1 + (long)local_14 * 8) = 0x3fd5555555555555;
        *(undefined8 *)(lParm1 + (long)(local_14 + 1) * 8) = 0x3fac71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 2) * 8) = 0x3fac71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 3) * 8) = 0x3fac71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 4) * 8) = 0x3fac71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 5) * 8) = 0x3fac71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 6) * 8) = 0x3fac71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 7) * 8) = 0x3f9c71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 8) * 8) = 0x3f9c71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 9) * 8) = 0x3f9c71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 10) * 8) = 0x3f9c71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 0xb) * 8) = 0x3f9c71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 0xc) * 8) = 0x3f9c71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 0xd) * 8) = 0x3f9c71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 0xe) * 8) = 0x3f9c71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 0xf) * 8) = 0x3f9c71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 0x10) * 8) = 0x3f9c71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 0x11) * 8) = 0x3f9c71c71c71c71c;
        *(undefined8 *)(lParm1 + (long)(local_14 + 0x12) * 8) = 0x3f9c71c71c71c71c;
        *(undefined4 *)(lParm1 + (long)(local_14 + 0x13) * 8) = 0;
        local_14 = local_14 + 0x14;
    }
    return;
}

undefined8 main(uint uParm1,undefined8 uParm2)

{
    long in_FS_OFFSET;
    uint local_3c;
    int local_38 [5];
    int local_24;
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    MAIN_parseCommandLine((ulong)uParm1,uParm2,local_38,uParm2);
    MAIN_printInfo(local_38);
    MAIN_initialize(local_38);
    local_3c = 1;
    while ((int)local_3c <= local_38[0]) {
        if (local_24 == 1) {
            LBM_handleInOutFlow(srcGrid);
        }
        LBM_performStreamCollide(srcGrid,dstGrid,dstGrid);
        LBM_swapGrids(&srcGrid,&dstGrid);
        if ((local_3c & 0x3f) == 0) {
            printf("timestep: %i\n",(ulong)local_3c);
            LBM_showGridStatistics(srcGrid);
        }
        local_3c = local_3c + 1;
    }
    MAIN_finalize(local_38);
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
    }
    return 0;
}

void LBM_loadObstacleFile(long lParm1,char *pcParm2)

{
    int iVar1;
    FILE *__stream;
    uint *puVar2;
    int local_24;
    int local_20;
    int local_1c;

    __stream = fopen(pcParm2,"rb");
    local_1c = 0;
    while (local_1c < 0x82) {
        local_20 = 0;
        while (local_20 < 100) {
            local_24 = 0;
            while (local_24 < 100) {
                iVar1 = fgetc(__stream);
                if (iVar1 != 0x2e) {
                    puVar2 = (uint *)(lParm1 + (long)(local_1c * 10000 + local_20 * 100 + local_24) * 0xa0 +
                            0x98);
                    *puVar2 = *puVar2 | 1;
                }
                local_24 = local_24 + 1;
            }
            fgetc(__stream);
            local_20 = local_20 + 1;
        }
        fgetc(__stream);
        local_1c = local_1c + 1;
    }
    fclose(__stream);
    return;
}

void LBM_allocateGrid(void **ppvParm1,undefined8 uParm2)

{
    void *pvVar1;

    pvVar1 = malloc(0xcc77c00);
    *ppvParm1 = pvVar1;
    if (*ppvParm1 != (void *)0x0) {
        *ppvParm1 = (void *)((long)*ppvParm1 + 3200000);
        return;
    }
    printf((char *)ZEXT816(0x40698ef800000000),"LBM_allocateGrid: could not allocate %.1f MByte\n",
            uParm2,pvVar1);
    /* WARNING: Subroutine does not return */
    exit(1);
}

void LBM_initializeSpecialCellsForChannel(long lParm1)

{
    uint *puVar1;
    int local_24;
    int local_20;
    int local_1c;

    local_1c = -2;
    while (local_1c < 0x84) {
        local_20 = 0;
        while (local_20 < 100) {
            local_24 = 0;
            while (local_24 < 100) {
                if ((((local_24 == 0) || (local_24 == 99)) || (local_20 == 0)) || (local_20 == 99)) {
                    puVar1 = (uint *)(lParm1 + (long)(local_1c * 10000 + local_20 * 100 + local_24) * 0xa0 +
                            0x98);
                    *puVar1 = *puVar1 | 1;
                    if (((local_1c == 0) || (local_1c == 0x81)) &&
                            ((*(uint *)(lParm1 + (long)(local_1c * 10000 + local_20 * 100 + local_24) * 0xa0 + 0x98
                                       ) & 1) == 0)) {
                        puVar1 = (uint *)(lParm1 + (long)(local_1c * 10000 + local_20 * 100 + local_24) * 0xa0 +
                                0x98);
                        *puVar1 = *puVar1 | 4;
                    }
                }
                local_24 = local_24 + 1;
            }
            local_20 = local_20 + 1;
        }
        local_1c = local_1c + 1;
    }
    return;
}

