
static void storeValue( FILE* file, float* v ) {
    const int litteBigEndianTest = 1;
    if( (*((unsigned char*) &litteBigEndianTest)) == 0 ) {
        const char* vPtr = (char*) v;
        char buffer[sizeof( float )];
        int i;

        for (i = 0; i < sizeof( float ); i++)
            buffer[i] = vPtr[sizeof( float ) - i - 1];

        fwrite( buffer, sizeof( float ), 1, file );
    }
    else {
        fwrite( v, sizeof( float ), 1, file );
    }
}



static void loadValue( FILE* file, float* v ) {
    const int litteBigEndianTest = 1;
    if( (*((unsigned char*) &litteBigEndianTest)) == 0 ) {
        char* vPtr = (char*) v;
        char buffer[sizeof( float )];
        int i;

        fread( buffer, sizeof( float ), 1, file );

        for (i = 0; i < sizeof( float ); i++)
            vPtr[i] = buffer[sizeof( float ) - i - 1];
    }
    else {
        fread( v, sizeof( float ), 1, file );
    }
}

void MAIN_initialize( const MAIN_Param* param ) {
    LBM_allocateGrid( (double**) &srcGrid );
    LBM_allocateGrid( (double**) &dstGrid );

    LBM_initializeGrid( *srcGrid );
    LBM_initializeGrid( *dstGrid );

    if( param->obstacleFilename != ((void *)0)) {
        LBM_loadObstacleFile( *srcGrid, param->obstacleFilename );
        LBM_loadObstacleFile( *dstGrid, param->obstacleFilename );
    }

    if( param->simType == CHANNEL ) {
        LBM_initializeSpecialCellsForChannel( *srcGrid );
        LBM_initializeSpecialCellsForChannel( *dstGrid );
    }
    else {
        LBM_initializeSpecialCellsForLDC( *srcGrid );
        LBM_initializeSpecialCellsForLDC( *dstGrid );
    }

    LBM_showGridStatistics( *srcGrid );
}



void LBM_storeVelocityField( LBM_Grid grid, const char* filename,
        const int binary ) {
    int x, y, z;
    float rho, ux, uy, uz;

    FILE* file = fopen( filename, (binary ? "wb" : "w") );

    for( z = 0; z < (130); z++ ) {
        for( y = 0; y < (1*(100)); y++ ) {
            for( x = 0; x < (1*(100)); x++ ) {
                rho = + ((grid)[((C)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((N)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((S)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((E)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((W)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((T)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((B)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((NE)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((NW)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((SE)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((SW)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((NT)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((NB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((ST)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((SB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((ET)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((EB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((WT)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((WB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]);
                ux = + ((grid)[((E)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((W)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((NE)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((NW)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((SE)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((SW)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((ET)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((EB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    - ((grid)[((WT)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((WB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]);
                uy = + ((grid)[((N)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((S)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((NE)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((NW)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    - ((grid)[((SE)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((SW)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((NT)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) + ((grid)[((NB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    - ((grid)[((ST)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((SB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]);
                uz = + ((grid)[((T)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((B)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((NT)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((NB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((ST)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((SB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((ET)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((EB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])
                    + ((grid)[((WT)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]) - ((grid)[((WB)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]);
                ux /= rho;
                uy /= rho;
                uz /= rho;

                if( binary ) {





                    storeValue( file, &ux );
                    storeValue( file, &uy );
                    storeValue( file, &uz );
                } else
                    fprintf( file, "%e %e %e\n", ux, uy, uz );

            }
        }
    }

    fclose( file );
}




void LBM_handleInOutFlow( LBM_Grid srcGrid ) {
    double ux , uy , uz , rho ,
           ux1, uy1, uz1, rho1,
           ux2, uy2, uz2, rho2,
           u2, px, py;
    int i;

    for( i = ((0)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100)))); i < ((0)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100)))); i += N_CELL_ENTRIES ) {
        rho1 = + ((srcGrid)[((C)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((N)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((S)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((E)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((W)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((T)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((B)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((SE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((SW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((ST)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((SB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((ET)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((EB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((WT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((WB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(1)*(1*(100))*(1*(100))))+(i)]);
        rho2 = + ((srcGrid)[((C)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((N)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((S)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((E)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((W)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((T)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((B)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((SE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((SW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((ST)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((SB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((ET)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((EB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((WT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((WB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(2)*(1*(100))*(1*(100))))+(i)]);

        rho = 2.0*rho1 - rho2;

        px = (((i / N_CELL_ENTRIES) % (1*(100))) / (0.5*((1*(100))-1))) - 1.0;
        py = ((((i / N_CELL_ENTRIES) / (1*(100))) % (1*(100))) / (0.5*((1*(100))-1))) - 1.0;
        ux = 0.00;
        uy = 0.00;
        uz = 0.01 * (1.0-px*px) * (1.0-py*py);

        u2 = 1.5 * (ux*ux + uy*uy + uz*uz);

        (((srcGrid)[((C)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/ 3.0)*rho*(1.0 - u2);

        (((srcGrid)[((N)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + uy*(4.5*uy + 3.0) - u2);
        (((srcGrid)[((S)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + uy*(4.5*uy - 3.0) - u2);
        (((srcGrid)[((E)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + ux*(4.5*ux + 3.0) - u2);
        (((srcGrid)[((W)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + ux*(4.5*ux - 3.0) - u2);
        (((srcGrid)[((T)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + uz*(4.5*uz + 3.0) - u2);
        (((srcGrid)[((B)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + uz*(4.5*uz - 3.0) - u2);

        (((srcGrid)[((NE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+ux+uy)*(4.5*(+ux+uy) + 3.0) - u2);
        (((srcGrid)[((NW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-ux+uy)*(4.5*(-ux+uy) + 3.0) - u2);
        (((srcGrid)[((SE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+ux-uy)*(4.5*(+ux-uy) + 3.0) - u2);
        (((srcGrid)[((SW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-ux-uy)*(4.5*(-ux-uy) + 3.0) - u2);
        (((srcGrid)[((NT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+uy+uz)*(4.5*(+uy+uz) + 3.0) - u2);
        (((srcGrid)[((NB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+uy-uz)*(4.5*(+uy-uz) + 3.0) - u2);
        (((srcGrid)[((ST)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-uy+uz)*(4.5*(-uy+uz) + 3.0) - u2);
        (((srcGrid)[((SB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-uy-uz)*(4.5*(-uy-uz) + 3.0) - u2);
        (((srcGrid)[((ET)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+ux+uz)*(4.5*(+ux+uz) + 3.0) - u2);
        (((srcGrid)[((EB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+ux-uz)*(4.5*(+ux-uz) + 3.0) - u2);
        (((srcGrid)[((WT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-ux+uz)*(4.5*(-ux+uz) + 3.0) - u2);
        (((srcGrid)[((WB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-ux-uz)*(4.5*(-ux-uz) + 3.0) - u2);
    }

    for( i = ((0)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+((130)-1)*(1*(100))*(1*(100)))); i < ((0)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+((130))*(1*(100))*(1*(100)))); i += N_CELL_ENTRIES ) {
        rho1 = + ((srcGrid)[((C)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((N)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((S)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((E)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((W)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((T)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((B)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((SE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((SW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((ST)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((SB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((ET)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((EB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((WT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((WB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]);
        ux1 = + ((srcGrid)[((E)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((W)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((NW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((SE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((SW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((ET)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((EB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            - ((srcGrid)[((WT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((WB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]);
        uy1 = + ((srcGrid)[((N)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((S)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            - ((srcGrid)[((SE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((SW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            - ((srcGrid)[((ST)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((SB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]);
        uz1 = + ((srcGrid)[((T)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((B)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((NB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((ST)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((SB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((ET)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((EB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((WT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((WB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-1)*(1*(100))*(1*(100))))+(i)]);

        ux1 /= rho1;
        uy1 /= rho1;
        uz1 /= rho1;

        rho2 = + ((srcGrid)[((C)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((N)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((S)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((E)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((W)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((T)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((B)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((SE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((SW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((ST)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((SB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((ET)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((EB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((WT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((WB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]);
        ux2 = + ((srcGrid)[((E)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((W)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((NW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((SE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((SW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((ET)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((EB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            - ((srcGrid)[((WT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((WB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]);
        uy2 = + ((srcGrid)[((N)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((S)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            - ((srcGrid)[((SE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((SW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) + ((srcGrid)[((NB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            - ((srcGrid)[((ST)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((SB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]);
        uz2 = + ((srcGrid)[((T)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((B)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((NT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((NB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((ST)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((SB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((ET)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((EB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)])
            + ((srcGrid)[((WT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]) - ((srcGrid)[((WB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100))))+(i)]);

        ux2 /= rho2;
        uy2 /= rho2;
        uz2 /= rho2;

        rho = 1.0;

        ux = 2*ux1 - ux2;
        uy = 2*uy1 - uy2;
        uz = 2*uz1 - uz2;

        u2 = 1.5 * (ux*ux + uy*uy + uz*uz);

        (((srcGrid)[((C)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/ 3.0)*rho*(1.0 - u2);

        (((srcGrid)[((N)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + uy*(4.5*uy + 3.0) - u2);
        (((srcGrid)[((S)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + uy*(4.5*uy - 3.0) - u2);
        (((srcGrid)[((E)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + ux*(4.5*ux + 3.0) - u2);
        (((srcGrid)[((W)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + ux*(4.5*ux - 3.0) - u2);
        (((srcGrid)[((T)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + uz*(4.5*uz + 3.0) - u2);
        (((srcGrid)[((B)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0)*rho*(1.0 + uz*(4.5*uz - 3.0) - u2);

        (((srcGrid)[((NE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+ux+uy)*(4.5*(+ux+uy) + 3.0) - u2);
        (((srcGrid)[((NW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-ux+uy)*(4.5*(-ux+uy) + 3.0) - u2);
        (((srcGrid)[((SE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+ux-uy)*(4.5*(+ux-uy) + 3.0) - u2);
        (((srcGrid)[((SW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-ux-uy)*(4.5*(-ux-uy) + 3.0) - u2);
        (((srcGrid)[((NT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+uy+uz)*(4.5*(+uy+uz) + 3.0) - u2);
        (((srcGrid)[((NB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+uy-uz)*(4.5*(+uy-uz) + 3.0) - u2);
        (((srcGrid)[((ST)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-uy+uz)*(4.5*(-uy+uz) + 3.0) - u2);
        (((srcGrid)[((SB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-uy-uz)*(4.5*(-uy-uz) + 3.0) - u2);
        (((srcGrid)[((ET)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+ux+uz)*(4.5*(+ux+uz) + 3.0) - u2);
        (((srcGrid)[((EB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (+ux-uz)*(4.5*(+ux-uz) + 3.0) - u2);
        (((srcGrid)[((WT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-ux+uz)*(4.5*(-ux+uz) + 3.0) - u2);
        (((srcGrid)[((WB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0)*rho*(1.0 + (-ux-uz)*(4.5*(-ux-uz) + 3.0) - u2);
    }
}



void LBM_initializeGrid( LBM_Grid grid ) {
    int i;







    for( i = ((0)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(-2)*(1*(100))*(1*(100)))); i < ((0)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+((130)+2)*(1*(100))*(1*(100)))); i += N_CELL_ENTRIES ) {
        (((grid)[((C)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/ 3.0);
        (((grid)[((N)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0);
        (((grid)[((S)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0);
        (((grid)[((E)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0);
        (((grid)[((W)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0);
        (((grid)[((T)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0);
        (((grid)[((B)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/18.0);
        (((grid)[((NE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);
        (((grid)[((NW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);
        (((grid)[((SE)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);
        (((grid)[((SW)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);
        (((grid)[((NT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);
        (((grid)[((NB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);
        (((grid)[((ST)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);
        (((grid)[((SB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);
        (((grid)[((ET)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);
        (((grid)[((EB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);
        (((grid)[((WT)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);
        (((grid)[((WB)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])) = (1.0/36.0);

        {unsigned int* const _aux_ = ((unsigned int*) ((void*) (&((((grid)[((FLAGS)+N_CELL_ENTRIES*((0)+ (0)*(1*(100))+(0)*(1*(100))*(1*(100))))+(i)])))))); (*_aux_) = 0;};
    }
}

int main( int nArgs, char* arg[] ) {
    MAIN_Param param;

    MAIN_Time time;

    int t;

    MAIN_parseCommandLine( nArgs, arg, &param );
    MAIN_printInfo( &param );
    MAIN_initialize( &param );

    MAIN_startClock( &time );


    for( t = 1; t <= param.nTimeSteps; t++ ) {
        if( param.simType == CHANNEL ) {
            LBM_handleInOutFlow( *srcGrid );
        }

        LBM_performStreamCollide( *srcGrid, *dstGrid );
        LBM_swapGrids( &srcGrid, &dstGrid );

        if( (t & 63) == 0 ) {
            printf( "timestep: %i\n", t );
            LBM_showGridStatistics( *srcGrid );
        }
    }


    MAIN_stopClock( &time, &param );

    MAIN_finalize( &param );

    return 0;
}



void LBM_loadObstacleFile( LBM_Grid grid, const char* filename ) {
    int x, y, z;

    FILE* file = fopen( filename, "rb" );

    for( z = 0; z < (130); z++ ) {
        for( y = 0; y < (1*(100)); y++ ) {
            for( x = 0; x < (1*(100)); x++ ) {
                if( fgetc( file ) != '.' ) {unsigned int* const _aux_ = ((unsigned int*) ((void*) (&(((grid)[((FLAGS)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]))))); (*_aux_) |= (OBSTACLE);};
            }
            fgetc( file );
        }
        fgetc( file );
    }

    fclose( file );
}


void LBM_allocateGrid( double** ptr ) {
    const size_t margin = 2*(1*(100))*(1*(100))*N_CELL_ENTRIES,
          size = sizeof( LBM_Grid ) + 2*margin*sizeof( double );

    *ptr = malloc( size );
    if( ! *ptr ) {
        printf( "LBM_allocateGrid: could not allocate %.1f MByte\n",
                size / (1024.0*1024.0) );
        exit( 1 );
    }

    printf( "LBM_allocateGrid: allocated %.1f MByte\n",
            size / (1024.0*1024.0) );

    *ptr += margin;
}




void LBM_initializeSpecialCellsForChannel( LBM_Grid grid ) {
    int x, y, z;







    for( z = -2; z < (130)+2; z++ ) {
        for( y = 0; y < (1*(100)); y++ ) {
            for( x = 0; x < (1*(100)); x++ ) {
                if( x == 0 || x == (1*(100))-1 ||
                        y == 0 || y == (1*(100))-1 ) {
                    {unsigned int* const _aux_ = ((unsigned int*) ((void*) (&(((grid)[((FLAGS)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]))))); (*_aux_) |= (OBSTACLE);};

                    if( (z == 0 || z == (130)-1) &&
                            ! ((*((unsigned int*) ((void*) (&(((grid)[((FLAGS)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))])))))) & (OBSTACLE)))
                    {unsigned int* const _aux_ = ((unsigned int*) ((void*) (&(((grid)[((FLAGS)+N_CELL_ENTRIES*((x)+ (y)*(1*(100))+(z)*(1*(100))*(1*(100))))]))))); (*_aux_) |= (IN_OUT_FLOW);};
                }
            }
        }
    }
}




