i32 wayobj::makebound2(i32pt bound1p, i32 bound1l, i32pt bound2p)
{
    i32 bound2l;
    i32 index,index1;
    i32 yoffset;
    waymapcellpt waymap;
    i32 i;

    yoffset=maply;
    waymap=wayobj::waymap;

    bound2l=0;
    for (i=0; i<bound1l; i++)
    {
        index=bound1p[i];

        index1=index-yoffset-1;
        if (waymap[index1].fillnum!=fillnum)
            if (maparp[index1]==0)
            {
                bound2p[bound2l]=index1;
                bound2l++;

                waymap[index1].fillnum=fillnum;
                waymap[index1].num=step;

                if (index1==endindex)
                {
                    flend=true;
                    return bound2l;
                }
            }

        index1=index-yoffset;
        if (waymap[index1].fillnum!=fillnum)
            if (maparp[index1]==0)
            {
                bound2p[bound2l]=index1;
                bound2l++;

                waymap[index1].fillnum=fillnum;
                waymap[index1].num=step;

                if (index1==endindex)
                {
                    flend=true;
                    return bound2l;
                }
            }

        index1=index-yoffset+1;
        if (waymap[index1].fillnum!=fillnum)
            if (maparp[index1]==0)
            {
                bound2p[bound2l]=index1;
                bound2l++;

                waymap[index1].fillnum=fillnum;
                waymap[index1].num=step;

                if (index1==endindex)
                {
                    flend=true;
                    return bound2l;
                }
            }

        index1=index-1;
        if (waymap[index1].fillnum!=fillnum)
            if (maparp[index1]==0)
            {
                bound2p[bound2l]=index1;
                bound2l++;

                waymap[index1].fillnum=fillnum;
                waymap[index1].num=step;

                if (index1==endindex)
                {
                    flend=true;
                    return bound2l;
                }
            }

        index1=index+1;
        if (waymap[index1].fillnum!=fillnum)
            if (maparp[index1]==0)
            {
                bound2p[bound2l]=index1;
                bound2l++;

                waymap[index1].fillnum=fillnum;
                waymap[index1].num=step;

                if (index1==endindex)
                {
                    flend=true;
                    return bound2l;
                }
            }


        index1=index+yoffset-1;
        if (waymap[index1].fillnum!=fillnum)
            if (maparp[index1]==0)
            {
                bound2p[bound2l]=index1;
                bound2l++;

                waymap[index1].fillnum=fillnum;
                waymap[index1].num=step;

                if (index1==endindex)
                {
                    flend=true;
                    return bound2l;
                }
            }

        index1=index+yoffset;
        if (waymap[index1].fillnum!=fillnum)
            if (maparp[index1]==0)
            {
                bound2p[bound2l]=index1;
                bound2l++;

                waymap[index1].fillnum=fillnum;
                waymap[index1].num=step;

                if (index1==endindex)
                {
                    flend=true;
                    return bound2l;
                }
            }

        index1=index+yoffset+1;
        if (waymap[index1].fillnum!=fillnum)
            if (maparp[index1]==0)
            {
                bound2p[bound2l]=index1;
                bound2l++;

                waymap[index1].fillnum=fillnum;
                waymap[index1].num=step;

                if (index1==endindex)
                {
                    flend=true;
                    return bound2l;
                }
            }

        if (bound2l>=maxboundlength)
            bound2l=maxboundlength-1;
    }

    return bound2l;
}




void regobj::create(i32 x0, i32 y0)
{
    bool newflodd;
    i32 x,y;
    i32 x1,y1,x2,y2;

    centerp.x=x0;
    centerp.y=y0;

    square=0;

    bound1arp.create(128);
    bound2arp.create(128);

    nb1ar.create(4);


    x1=x0-1;
    y1=y0-1;

    x2=x0+1;
    y2=y0+1;

    if (x1<0) x1=0;
    if (y1<0) y1=0;

    if (x2>regmngp->mapmaxx) x2=regmngp->mapmaxx;
    if (y2>regmngp->mapmaxy) y2=regmngp->mapmaxy;

    for (y=y1; y<=y2; y++)
        for (x=x1; x<=x2; x++)
            if (regmngp->regmapp(x,y)==
# 87 "Region_.cpp" 3 4
                    __null
# 87 "Region_.cpp"
               )
                addtobound(bound1arp,x,y);

    boundl=bound1arp.elemqu;


    if (boundl!=0)
        flexist=true;
    else
    {
        flexist=false;

        bound1arp.destroy();
        bound2arp.destroy();

        return;
    }

    flodd=false;

    while (boundl!=0)
    {
        if (flodd==false)
        {
            makebound2(bound1arp,bound2arp);
            newflodd=true;
            boundl=bound2arp.elemqu;
        }
        else
        {
            makebound2(bound2arp,bound1arp);
            newflodd=false;
            boundl=bound1arp.elemqu;
        }

        flodd=newflodd;
    }

    bound1arp.destroy();
    bound2arp.destroy();
}

void regmngobj::foundemptyregions()
{
    i32 i;

    for (i=0; i<rarp.elemqu; i++)
        if (rarp[i]->square==0)
            rarp[i]->flexist=false;
}

bool wayobj::createway(const rvectort& startp, const rvectort& finishp, bool flcorrect, wayinfot& wayinfo)
{
    i32 startx,starty;
    i32 endx,endy;
    bool flcorrectend;


    createwayinfo.startp=startp;
    createwayinfo.finishp=finishp;
    createwayinfo.flcorrect=flcorrect;

    startx=getx(startp.x);
    starty=gety(startp.z);

    endx=getx(finishp.x);
    endy=gety(finishp.z);

    flcorrectend=false;

    if ((!ismap(startx,starty))||(!ismap(endx,endy)))
    {
        wayinfo.flexist=false;
        wayinfo.wayarp=
# 617 "CreateWay_.cpp" 3 4
            __null
# 617 "CreateWay_.cpp"
            ;
        wayinfo.wayarsize=0;
        wayinfo.flcorrect=flcorrectend;
        return false;
    }


    if (map(endx,endy)!=0)
        if (flcorrect==false)
        {
            wayinfo.flexist=false;
            wayinfo.wayarp=
# 628 "CreateWay_.cpp" 3 4
                __null
# 628 "CreateWay_.cpp"
                ;
            wayinfo.wayarsize=0;
            wayinfo.flcorrect=flcorrectend;
            return false;
        }
        else
        {
            if (findfreepoint(endx,endy,endx,endy)==false)
            {
                wayinfo.flexist=false;
                wayinfo.wayarp= __null;

                wayinfo.wayarsize=0;
                wayinfo.flcorrect=flcorrectend;
                return false;
            }
            else
            {
                flcorrectend=true;
                createwayinfo.finishp=getpoint(index(endx,endy));
            }
        }


    if ((startx==endx)&&(starty==endy))
    {
        wayinfo.flexist=true;
        wayinfo.wayarp=new rvectort[2];
        wayinfo.wayarp[0]=startp;
        wayinfo.wayarp[1]=createwayinfo.finishp;
        wayinfo.wayarsize=2;
        wayinfo.flcorrect=flcorrectend;
        return true;
    }


    if (!fill(startx,starty,endx,endy))
    {
        wayinfo.flexist=false;
        wayinfo.wayarp=
# 666 "CreateWay_.cpp" 3 4
            __null
# 666 "CreateWay_.cpp"
            ;
        wayinfo.wayarsize=0;
        wayinfo.flcorrect=flcorrectend;
        return false;
    }


    wayinfo.flcorrect=flcorrectend;
    if (!createwayar(index(startx,starty),endindex,wayinfo))
    {
        wayinfo.flexist=false;
        wayinfo.wayarp=
# 677 "CreateWay_.cpp" 3 4
            __null
# 677 "CreateWay_.cpp"
            ;
        wayinfo.wayarsize=0;
        wayinfo.flcorrect=flcorrectend;
        return false;
    }

    return true;
}

void way2obj::releasebound()
{
    i32 i;

    if (boundar[curbound].elemqu==0)
        nonboundqu=nonboundqu+1;
    else
    {
        nonboundqu=0;

        for (i=boundar[curbound].elemqu-1; i>=0; i--)
            releasepoint(boundar[curbound][i].x,boundar[curbound][i].y);

        boundar[curbound].clear();
    }
}



void regmngobj::addallregions()
{
    i32 x,y;

    for (y=0; y<=mapmaxy; y++)
        for (x=0; x<=mapmaxx; x++)
            if (regmapp(x,y)==
# 281 "RegMng_.cpp" 3 4
                    __null
# 281 "RegMng_.cpp"
               )
                if (flpasablear[mapp(x,y)])
                    newregion(x,y);
}


bool way2obj::fill(i32 startx, i32 starty)
{
    i32 i;

    for (i=0; i<maxmovetact+1; i++)
        boundar[i].clear();

    fillnum++;
    if (fillnum==65535)
    {
        memset(waymap,0,mapsizex*mapsizey*sizeof(waymap[0]));
        fillnum=1;
    }

    flend=false;

    nonboundqu=0;

    boundar[0].add(pointt(startx,starty));
    waymap[startx+starty*mapsizex].num=0;
    curbound=0;
    filltact=0;

    while ((flend==false)&&(nonboundqu<(maxmovetact+10)))
    {
        curbound=filltact%(maxmovetact+1);

        releasebound();

        filltact++;
    }

    return flend;
}



bool regmngobj::loadmap(const char* fn)
{
    int hf;
    i32 i;


    hf=open(fn,
# 57 "RegMng_.cpp" 3 4
            00
# 57 "RegMng_.cpp"
           );




    if (hf==-1)
        return false;
# 77 "RegMng_.cpp"
    read(hf,&mapsizex,sizeof(mapsizex));
    read(hf,&mapsizey,sizeof(mapsizey));


    mapmaxx=mapsizex-1;
    mapmaxy=mapsizey-1;

    regionmapp=(regobjppt)malloc(mapsizex*mapsizey*sizeof(regionmapp[0]));
    landscapemapp=(bytept)malloc(mapsizex*mapsizey*sizeof(landscapemapp[0]));
    mmapp=(w16pt)malloc(mapsizex*mapsizey*sizeof(mmapp[0]));
    memset(mmapp,0,mapsizex*mapsizey*sizeof(mmapp[0]));
    fillnum=0;

    read(hf,landscapemapp,mapsizex*mapsizey*sizeof(landscapemapp[0]));

    for (i=0; i<256; i++)
        flpasablear[i]=false;
    flpasablear[0]=true;

    close(hf);

    return true;
}


void regmngobj::defineregions()
{
    i32 i;
    i32 x,y,xx,yy;
    flexarray <regboundobj> rboundarp;
    i32 regionx,regiony;
    bool fldone;
    i32 i1,i2;
    i32 reglx,regly;
    regobjpt regionp;
    regboundobjpt regboundp;


    rboundarp.create(16);
# 191 "RegMng_.cpp"
    regionx=round((mapmaxx/620.0f)*34.0f/radiuscoef);
    regiony=round((mapmaxy/309.0f)*20.0f/radiuscoef);

    reglx=round((mapmaxx+1)/(rnumt)regionx);
    regly=round((mapmaxy+1)/(rnumt)regiony*sqrt(3.0f)/2.0f);


    i1=0;
    i2=0;

    do
    {
        if (i2&1)
            xx=reglx+i1*reglx;
        else
            xx=(reglx / 2)+i1*reglx;

        yy=(regly / 2)+i2*regly;

        if (findfreeplace(xx,yy,x,y)==false)
            goto next;
        else
            if (regmapp(x,y))
                goto next;

        regionp=new regobj(this);
        regionp->internalnum=rarp.add(regionp);
        regionp->create();
        regionp->flexist=true;
        regionp->centerp.x=x;
        regionp->centerp.y=y;

        regboundp=rboundarp.add();
        regboundp->flexist=true;
        regboundp->firststep(x,y,regionp,this);

next:

        i1=i1+1;

        if (i2&1)
        {
            if (i1==regionx-1)
            {
                i1=0;
                i2=i2+1;
            }
        }
        else
        {
            if (i1==regionx)
            {
                i1=0;
                i2=i2+1;
            }
        }
    }



    while (i2<round(regiony*2.0f/sqrt(3.0f))+3);


    do
    {
        fldone=true;

        for (i=0; i<rboundarp.elemqu; i++)
            if (rboundarp[i].step()==true)
                fldone=false;

    }
    while (fldone==false);


    for (i=0; i<rboundarp.elemqu; i++)
        rboundarp[i].destroy();
    rboundarp.destroy();
}


