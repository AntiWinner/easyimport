int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  unsigned int v4; // er9
  _DWORD *v5; // r15
  void *v6; // rbx
  void (__fastcall *v7)(_QWORD, const char *, const char *, _QWORD); // rbx
  unsigned int v8; // ecx
  unsigned int v9; // edx
  __int64 v10; // r8
  struct _PEB *v11; // rax
  _LIST_ENTRY *Flink; // r14
  _LIST_ENTRY *v13; // rdi
  int v14; // ebp
  int v15; // eax
  _LIST_ENTRY *v16; // rsi
  _LIST_ENTRY *v17; // r9
  unsigned int v18; // er10
  __int16 v19; // r11
  __int64 v20; // rax
  __int64 v21; // rcx
  bool v22; // cf
  __int64 v23; // rax
  int v24; // ecx
  int v25; // er8
  int v26; // edx
  int v27; // ecx
  __int64 library; // rbp
  struct _PEB *v29; // rax
  _LIST_ENTRY *v30; // r14
  _LIST_ENTRY *v31; // rdi
  int v32; // ebp
  int v33; // eax
  _LIST_ENTRY *v34; // rsi
  _LIST_ENTRY *v35; // r9
  unsigned int v36; // er10
  __int16 v37; // r11
  __int64 v38; // rax
  __int64 v39; // rcx
  __int64 v40; // rax
  int v41; // er8
  int v42; // ecx
  int v43; // edx
  int v44; // ecx
  _LIST_ENTRY *v45; // r14
  __int64 v46; // rcx
  __int64 (__fastcall *v47)(_QWORD); // rax
  __int64 v48; // rcx
  __int64 v49; // r12
  __int64 v50; // r13
  __int64 v51; // rbp
  unsigned int *v52; // r15
  _BYTE *v53; // rsi
  __int64 v54; // rdi
  __m128i *v55; // r9
  unsigned int v56; // eax
  __int64 v57; // r8
  __int64 v58; // rdx
  _BYTE *v59; // rcx
  __m128i *v60; // rdx
  __m128i v61; // xmm0
  __m128i v62; // xmm1
  __m128i v63; // xmm0
  __m128i v64; // xmm1
  char *v65; // rcx
  __m128i *v66; // rdx
  __int64 v67; // r8
  unsigned int v68; // er10
  __int16 v69; // r11
  __int64 v70; // rax
  __int64 v71; // rcx
  __int64 v72; // rax
  int v73; // ecx
  int v74; // er8
  int v75; // edx
  int v76; // ecx
  __int64 v77; // rcx
  __int64 v78; // rcx
  __int64 v79; // r12
  __int64 v80; // r13
  __int64 v81; // r14
  unsigned int *v82; // r15
  _BYTE *v83; // rsi
  __int64 v84; // rdi
  __m128i *v85; // r9
  unsigned int v86; // eax
  __int64 v87; // r8
  __int64 v88; // rdx
  _BYTE *v89; // rcx
  __m128i *v90; // rdx
  __m128i v91; // xmm0
  __m128i v92; // xmm1
  __m128i v93; // xmm0
  __m128i v94; // xmm1
  char *v95; // rcx
  __m128i *v96; // rdx
  __int64 v97; // r8
  unsigned int v98; // er10
  __int16 v99; // r11
  __int64 v100; // rax
  __int64 v101; // rcx
  __int64 v102; // rax
  int v103; // er8
  int v104; // ecx
  int v105; // edx
  int v106; // ecx
  unsigned int v107; // ecx
  __int128 v109; // [rsp+20h] [rbp-48h]
  unsigned int v110; // [rsp+70h] [rbp+8h]
  __int64 v111; // [rsp+78h] [rbp+10h]
  __int64 v112; // [rsp+78h] [rbp+10h]

  v3 = easyimport::utils::crc32<20>(*(const wchar_t **)&argc);
  v4 = ~(easyimport::utils::crc_table[(unsigned __int8)(LOBYTE(easyimport::utils::crc_table[(unsigned __int8)(aIMAMessageBox[10] ^ v3)]) ^ BYTE1(v3) ^ aIMAMessageBox[12])] ^ ((easyimport::utils::crc_table[(unsigned __int8)(aIMAMessageBox[10] ^ v3)] ^ (v3 >> 8)) >> 8));
  v110 = v4;
  v5 = (_DWORD *)(*(_QWORD *)NtCurrentTeb()->Reserved1[11] + 4i64);
  if ( __TSS0__1__get_function_addressex_cached_easyimport__YA_KKPEB_W0_Z_4HA > *v5 )
  {
    Init_thread_header(&__TSS0__1__get_function_addressex_cached_easyimport__YA_KKPEB_W0_Z_4HA);
    if ( __TSS0__1__get_function_addressex_cached_easyimport__YA_KKPEB_W0_Z_4HA == -1 )
    {
      `easyimport::get_function_addressex_cached'::`2'::images = 0i64;
      v6 = operator new[](0x4000ui64);
      memset_0(v6, 0i64, 0x4000i64);
      *(_QWORD *)&`easyimport::get_function_addressex_cached'::`2'::images = v6;
      Init_thread_footer(&__TSS0__1__get_function_addressex_cached_easyimport__YA_KKPEB_W0_Z_4HA);
    }
    v4 = v110;
  }
  v7 = 0i64;
  v8 = 0;
  v9 = DWORD2(`easyimport::get_function_addressex_cached'::`2'::images);
  if ( DWORD2(`easyimport::get_function_addressex_cached'::`2'::images) )
  {
    v10 = `easyimport::get_function_addressex_cached'::`2'::images;
    while ( *(_DWORD *)(`easyimport::get_function_addressex_cached'::`2'::images + 16i64 * v8) != v4 )
    {
      if ( ++v8 >= DWORD2(`easyimport::get_function_addressex_cached'::`2'::images) )
        goto LABEL_9;
    }
  }
  else
  {
LABEL_9:
    LODWORD(v109) = v4;
    v11 = NtCurrentPeb();
    if ( v11 )
    {
      Flink = v11->Ldr->InMemoryOrderModuleList.Flink;
      v13 = Flink;
      v14 = 0;
      do
      {
        v15 = v14++;
        if ( v15 > 64 )
          break;
        v16 = v13 - 1;
        if ( v13 != (_LIST_ENTRY *)16 )
        {
          v17 = v16[6].Flink;
          if ( v17 )
          {
            v18 = 0;
            v19 = (__int16)v17->Flink;
            while ( 1 )
            {
              v20 = 0i64;
              if ( v19 )
              {
                do
                  ++v20;
                while ( *((_WORD *)&v17->Flink + v20) );
              }
              v21 = 0i64;
              do
                ++v21;
              while ( aUser32Dll[v21] );
              v22 = (unsigned int)v20 < (unsigned int)v21;
              v23 = 0i64;
              if ( v22 )
              {
                if ( v19 )
                {
                  do
                    ++v23;
                  while ( *((_WORD *)&v17->Flink + v23) );
                }
              }
              else
              {
                do
                  ++v23;
                while ( aUser32Dll[v23] );
              }
              if ( v18 >= (unsigned int)v23 )
                break;
              v24 = *((unsigned __int16 *)&v17->Flink + v18);
              v25 = aUser32Dll[v18];
              v26 = v24 + 32;
              if ( (unsigned int)(v24 - 65) > 0x19 )
                v26 = *((unsigned __int16 *)&v17->Flink + v18);
              v27 = v25 + 32;
              if ( (unsigned int)(v25 - 65) > 0x19 )
                v27 = aUser32Dll[v18];
              if ( v26 != v27 )
              {
                v13 = v13->Flink;
                goto LABEL_32;
              }
              ++v18;
            }
            library = (__int64)v16[3].Flink;
            if ( library )
              goto LABEL_102;
            break;
          }
        }
LABEL_32:
        ;
      }
      while ( v13 != Flink );
    }
    if ( __TSS0__4__get_image_base_utils_easyimport__YA_KPEB_W_Z_4HA > *v5 )
    {
      Init_thread_header(&__TSS0__4__get_image_base_utils_easyimport__YA_KPEB_W_Z_4HA);
      if ( __TSS0__4__get_image_base_utils_easyimport__YA_KPEB_W_Z_4HA == -1 )
      {
        v29 = NtCurrentPeb();
        if ( v29 )
        {
          v30 = v29->Ldr->InMemoryOrderModuleList.Flink;
          v31 = v30;
          v32 = 0;
          do
          {
            v33 = v32++;
            if ( v33 > 64 )
              break;
            v34 = v31 - 1;
            if ( v31 != (_LIST_ENTRY *)16 )
            {
              v35 = v34[6].Flink;
              if ( v35 )
              {
                v36 = 0;
                v37 = (__int16)v35->Flink;
                while ( 1 )
                {
                  v38 = 0i64;
                  if ( v37 )
                  {
                    do
                      ++v38;
                    while ( *((_WORD *)&v35->Flink + v38) );
                  }
                  v39 = 0i64;
                  do
                    ++v39;
                  while ( *((_WORD *)&type_info::`vftable'[1] + v39) );
                  v22 = (unsigned int)v38 < (unsigned int)v39;
                  v40 = 0i64;
                  if ( v22 )
                  {
                    if ( v37 )
                    {
                      do
                        ++v40;
                      while ( *((_WORD *)&v35->Flink + v40) );
                    }
                  }
                  else
                  {
                    do
                      ++v40;
                    while ( *((_WORD *)&type_info::`vftable'[1] + v40) );
                  }
                  if ( v36 >= (unsigned int)v40 )
                    break;
                  v41 = *((unsigned __int16 *)&v35->Flink + v36);
                  v42 = *((unsigned __int16 *)&type_info::`vftable'[1] + v36);
                  v43 = v42 + 32;
                  if ( (unsigned int)(v42 - 65) > 0x19 )
                    v43 = *((unsigned __int16 *)&type_info::`vftable'[1] + v36);
                  v44 = v41 + 32;
                  if ( (unsigned int)(v41 - 65) > 0x19 )
                    v44 = *((unsigned __int16 *)&v35->Flink + v36);
                  if ( v44 != v43 )
                  {
                    v31 = v31->Flink;
                    goto LABEL_60;
                  }
                  ++v36;
                }
                v45 = v34[3].Flink;
                goto LABEL_62;
              }
            }
LABEL_60:
            ;
          }
          while ( v31 != v30 );
        }
        v45 = 0i64;
LABEL_62:
        v46 = *(unsigned int *)((char *)&v45[8].Blink + SHIDWORD(v45[3].Blink));
        if ( (_DWORD)v46 )
        {
          v48 = (__int64)v45 + v46;
          v49 = *(int *)(v48 + 24);
          if ( (_DWORD)v49 )
          {
            v50 = (__int64)v45 + *(unsigned int *)(v48 + 28);
            v111 = (__int64)v45 + *(unsigned int *)(v48 + 36);
            v51 = *(int *)(v48 + 24);
            v52 = (unsigned int *)((char *)v45 + 4 * v49 + *(unsigned int *)(v48 + 32) - 4);
            while ( 2 )
            {
              v53 = (char *)v45 + *v52;
              v54 = 0i64;
              if ( *v53 )
              {
                do
                  ++v54;
                while ( v53[v54] );
              }
              v55 = (__m128i *)operator new[](saturated_mul((unsigned int)v54, 2ui64));
              v56 = 0;
              v57 = 0i64;
              if ( (_DWORD)v54 )
              {
                if ( (unsigned int)v54 >= 0x20 )
                {
                  v58 = (int)v54 - 1;
                  if ( v55 > (__m128i *)&v53[v58] || (char *)v55 + 2 * v58 < v53 )
                  {
                    v59 = v53 + 16;
                    v60 = v55 + 2;
                    do
                    {
                      v61 = _mm_loadl_epi64((const __m128i *)v59 - 1);
                      v60[-2] = _mm_srai_epi16(_mm_unpacklo_epi8(v61, v61), 8u);
                      v62 = _mm_loadl_epi64((const __m128i *)(v59 - 8));
                      v60[-1] = _mm_srai_epi16(_mm_unpacklo_epi8(v62, v62), 8u);
                      v63 = _mm_loadl_epi64((const __m128i *)v59);
                      *v60 = _mm_srai_epi16(_mm_unpacklo_epi8(v63, v63), 8u);
                      v64 = _mm_loadl_epi64((const __m128i *)(v59 + 8));
                      v60[1] = _mm_srai_epi16(_mm_unpacklo_epi8(v64, v64), 8u);
                      v56 += 32;
                      v57 += 4i64;
                      v60 += 4;
                      v59 += 32;
                    }
                    while ( v56 < ((unsigned int)v54 & 0xFFFFFFE0) );
                  }
                }
                if ( v56 < (unsigned int)v54 )
                {
                  v65 = &v53[v57 * 8];
                  v66 = &v55[v57];
                  v67 = (unsigned int)v54 - v56;
                  do
                  {
                    v66->m128i_i16[0] = *v65++;
                    v66 = (__m128i *)((char *)v66 + 2);
                    --v67;
                  }
                  while ( v67 );
                }
              }
              v68 = 0;
              v69 = v55->m128i_i16[0];
              while ( 1 )
              {
                v70 = 0i64;
                if ( v69 )
                {
                  do
                    ++v70;
                  while ( v55->m128i_i16[v70] );
                }
                v71 = 0i64;
                do
                  ++v71;
                while ( aLoadlibraryw[v71] );
                v22 = (unsigned int)v70 < (unsigned int)v71;
                v72 = 0i64;
                if ( v22 )
                {
                  if ( v69 )
                  {
                    do
                      ++v72;
                    while ( v55->m128i_i16[v72] );
                  }
                }
                else
                {
                  do
                    ++v72;
                  while ( aLoadlibraryw[v72] );
                }
                if ( v68 >= (unsigned int)v72 )
                {
                  v47 = (__int64 (__fastcall *)(_QWORD))((char *)v45
                                                       + *(unsigned int *)(v50
                                                                         + 4i64
                                                                         * *(unsigned __int16 *)(v111
                                                                                               + 2i64 * (int)v49
                                                                                               - 2)));
                  goto LABEL_99;
                }
                v73 = v55->m128i_u16[v68];
                v74 = aLoadlibraryw[v68];
                v75 = v73 + 32;
                if ( (unsigned int)(v73 - 65) > 0x19 )
                  v75 = v55->m128i_u16[v68];
                v76 = v74 + 32;
                if ( (unsigned int)(v74 - 65) > 0x19 )
                  v76 = aLoadlibraryw[v68];
                if ( v75 != v76 )
                  break;
                ++v68;
              }
              LODWORD(v49) = v49 - 1;
              --v52;
              if ( --v51 )
                continue;
              break;
            }
            v47 = 0i64;
          }
          else
          {
            v47 = 0i64;
          }
        }
        else
        {
          v47 = 0i64;
        }
LABEL_99:
        `easyimport::utils::get_image_base'::`5'::load_library = v47;
        Init_thread_footer(&__TSS0__4__get_image_base_utils_easyimport__YA_KPEB_W_Z_4HA);
      }
    }
    library = `easyimport::utils::get_image_base'::`5'::load_library(L"user32.dll");
    if ( !library )
      library = 0i64;
LABEL_102:
    v77 = *(unsigned int *)(*(int *)(library + 60) + library + 136);
    if ( (_DWORD)v77 )
    {
      v78 = library + v77;
      v79 = *(int *)(v78 + 24);
      if ( (_DWORD)v79 )
      {
        v80 = library + *(unsigned int *)(v78 + 28);
        v112 = library + *(unsigned int *)(v78 + 36);
        v81 = *(int *)(v78 + 24);
        v82 = (unsigned int *)(library + *(unsigned int *)(v78 + 32) + 4 * (v79 - 1));
        while ( 2 )
        {
          v83 = (_BYTE *)(library + *v82);
          v84 = 0i64;
          if ( *v83 )
          {
            do
              ++v84;
            while ( v83[v84] );
          }
          v85 = (__m128i *)operator new[](saturated_mul((unsigned int)v84, 2ui64));
          v86 = 0;
          v87 = 0i64;
          if ( (_DWORD)v84 )
          {
            if ( (unsigned int)v84 >= 0x20 )
            {
              v88 = (int)v84 - 1;
              if ( v85 > (__m128i *)&v83[v88] || (char *)v85 + 2 * v88 < v83 )
              {
                v89 = v83 + 16;
                v90 = v85 + 2;
                do
                {
                  v91 = _mm_loadl_epi64((const __m128i *)v89 - 1);
                  v90[-2] = _mm_srai_epi16(_mm_unpacklo_epi8(v91, v91), 8u);
                  v92 = _mm_loadl_epi64((const __m128i *)(v89 - 8));
                  v90[-1] = _mm_srai_epi16(_mm_unpacklo_epi8(v92, v92), 8u);
                  v93 = _mm_loadl_epi64((const __m128i *)v89);
                  *v90 = _mm_srai_epi16(_mm_unpacklo_epi8(v93, v93), 8u);
                  v94 = _mm_loadl_epi64((const __m128i *)(v89 + 8));
                  v90[1] = _mm_srai_epi16(_mm_unpacklo_epi8(v94, v94), 8u);
                  v86 += 32;
                  v87 += 4i64;
                  v90 += 4;
                  v89 += 32;
                }
                while ( v86 < ((unsigned int)v84 & 0xFFFFFFE0) );
              }
            }
            if ( v86 < (unsigned int)v84 )
            {
              v95 = &v83[v87 * 8];
              v96 = &v85[v87];
              v97 = (unsigned int)v84 - v86;
              do
              {
                v96->m128i_i16[0] = *v95++;
                v96 = (__m128i *)((char *)v96 + 2);
                --v97;
              }
              while ( v97 );
            }
          }
          v98 = 0;
          v99 = v85->m128i_i16[0];
          while ( 1 )
          {
            v100 = 0i64;
            if ( v99 )
            {
              do
                ++v100;
              while ( v85->m128i_i16[v100] );
            }
            v101 = 0i64;
            do
              ++v101;
            while ( aMessageboxa[v101] );
            v22 = (unsigned int)v100 < (unsigned int)v101;
            v102 = 0i64;
            if ( v22 )
            {
              if ( v99 )
              {
                do
                  ++v102;
                while ( v85->m128i_i16[v102] );
              }
            }
            else
            {
              do
                ++v102;
              while ( aMessageboxa[v102] );
            }
            if ( v98 >= (unsigned int)v102 )
            {
              *((_QWORD *)&v109 + 1) = library
                                     + *(unsigned int *)(v80 + 4i64 * *(unsigned __int16 *)(v112 + 2i64 * (int)v79 - 2));
              goto LABEL_135;
            }
            v103 = v85->m128i_u16[v98];
            v104 = aMessageboxa[v98];
            v105 = v104 + 32;
            if ( (unsigned int)(v104 - 65) > 0x19 )
              v105 = aMessageboxa[v98];
            v106 = v103 + 32;
            if ( (unsigned int)(v103 - 65) > 0x19 )
              v106 = v85->m128i_u16[v98];
            if ( v106 != v105 )
              break;
            ++v98;
          }
          LODWORD(v79) = v79 - 1;
          --v82;
          if ( --v81 )
            continue;
          break;
        }
      }
    }
    *((_QWORD *)&v109 + 1) = 0i64;
LABEL_135:
    *(_OWORD *)(`easyimport::get_function_addressex_cached'::`2'::images
              + 16i64 * DWORD2(`easyimport::get_function_addressex_cached'::`2'::images)) = v109;
    v9 = ++DWORD2(`easyimport::get_function_addressex_cached'::`2'::images);
    v10 = `easyimport::get_function_addressex_cached'::`2'::images;
    v4 = v110;
  }
  v107 = 0;
  if ( v9 )
  {
    while ( *(_DWORD *)(v10 + 16i64 * v107) != v4 )
    {
      if ( ++v107 >= v9 )
        goto LABEL_142;
    }
    v7 = *(void (__fastcall **)(_QWORD, const char *, const char *, _QWORD))(v10 + 16i64 * v107 + 8);
  }
LABEL_142:
  v7(0i64, "I'm a message box", "Wowww", 0i64);
  return 0;
}