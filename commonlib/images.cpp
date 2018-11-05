//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "images.h"

namespace commonlib {

#define IS_WIN30_DIB(lpbi)  ((*(LPDWORD)(lpbi)) == sizeof(BITMAPINFOHEADER))
#define WIDTHBYTES(i)   ((i+31)/32*4)   // Round off to the closest byte

WORD DIBNumColors(LPSTR lpDIB);
WORD PaletteSize(LPSTR lpDIB);


HICON GetIcon(const wchar_t *FileName)
{
	HINSTANCE hInstance = GetModuleHandle(NULL);
	HICON hIcon = ExtractIcon(hInstance, FileName, 0);
	if ( hIcon == NULL || hIcon == (HICON)1 ) {
		CoInitialize(NULL);
		SHFILEINFO Info;
		if ( SHGetFileInfo(FileName, 0, &Info, sizeof Info, SHGFI_ICON) ) {
			hIcon = Info.hIcon;
		}
		CoUninitialize();
	}

	return hIcon;
}

size_t GetIcon(const wchar_t *FileName, byte *Buf, size_t BufSize)
{
	HICON hIcon = GetIcon(FileName);
	if ( hIcon == NULL ) return 0;

	return Hicon2Bytes(hIcon, Buf, BufSize);
}

WORD DIBNumColors(LPSTR lpDIB)
{
    WORD wBitCount;  // DIB bit count

	if (!lpDIB)
		return (WORD) 0;

    // If this is a Windows-style DIB, the number of colors in the
    // color table can be less than the number of bits per pixel
    // allows for (i.e. lpbi->biClrUsed can be set to some value).
    // If this is the case, return the appropriate value.
    

    if (IS_WIN30_DIB(lpDIB))
    {
        DWORD dwClrUsed;

        dwClrUsed = ((LPBITMAPINFOHEADER)lpDIB)->biClrUsed;
        if (dwClrUsed)

        return (WORD)dwClrUsed;
    }

    // Calculate the number of colors in the color table based on
    // the number of bits per pixel for the DIB.
    
    if (IS_WIN30_DIB(lpDIB))
        wBitCount = ((LPBITMAPINFOHEADER)lpDIB)->biBitCount;
    else
        wBitCount = ((LPBITMAPCOREHEADER)lpDIB)->bcBitCount;

    // return number of colors based on bits per pixel

    switch (wBitCount)
    {
        case 1:
            return 2;

        case 4:
            return 16;

        case 8:
            return 256;

        default:
            return 0;
    }
}

WORD PaletteSize(LPSTR lpDIB)
{
	if (!lpDIB)
		return (WORD) 0;

    // calculate the size required by the palette
    if (IS_WIN30_DIB (lpDIB))
        return (DIBNumColors(lpDIB) * sizeof(RGBQUAD));
    else
        return (DIBNumColors(lpDIB) * sizeof(RGBTRIPLE));
}

size_t GetBitMapBuffer(HBITMAP hBitmap, byte **Buf)
{
	*Buf = NULL;
	BITMAP bm;
    if ( GetObject(hBitmap, sizeof bm, (LPSTR)&bm) == 0 ) return 0;

	WORD Bits = bm.bmPlanes * bm.bmBitsPixel;
	if ( Bits <= 1 ) Bits = 1;
	else 
	if ( Bits <= 4 ) Bits = 4;
	else 
	if ( Bits <= 8 ) Bits = 8;
	else
	Bits = 8;

	HDC hDC = GetDC(NULL);
	BITMAPINFOHEADER bih = { 0 };
	bih.biSize = sizeof BITMAPINFOHEADER;
    bih.biWidth = bm.bmWidth;
    bih.biHeight = bm.bmHeight;
    bih.biPlanes = 1;
    bih.biBitCount = Bits;
    bih.biCompression = BI_RGB;

	PBITMAPINFO bi = (PBITMAPINFO) new byte[sizeof BITMAPINFOHEADER + PaletteSize((LPSTR)&bih)];
	bi->bmiHeader = bih;

	int Num = GetDIBits(hDC, hBitmap, 0, bm.bmHeight, NULL, bi, DIB_RGB_COLORS);
	if ( Num == 0 ) {
		delete[] bi;
		ReleaseDC(NULL, hDC);
		return 0;
	}

    // If the driver did not fill in the biSizeImage field, make one up
	if ( bi->bmiHeader.biSizeImage == 0 ) {
		bi->bmiHeader.biBitCount = Bits;
		bi->bmiHeader.biSizeImage = //WIDTHBYTES((DWORD)bm.bmWidth * Bits) * bm.bmHeight;
			((bi->bmiHeader.biWidth * Bits +31) & ~31) /8 * bi->bmiHeader.biHeight; 

		if ( bi->bmiHeader.biCompression != BI_RGB)
			bi->bmiHeader.biSizeImage = ( bi->bmiHeader.biSizeImage * 3 ) / 2;
	}

	size_t Length = bi->bmiHeader.biSize + PaletteSize((LPSTR)&bi->bmiHeader) + bi->bmiHeader.biSizeImage;
	byte *BitmapBuf = new byte[Length];
	PBITMAPINFO BitmapInfo = (PBITMAPINFO) BitmapBuf;
	memcpy(BitmapBuf, bi, bi->bmiHeader.biSize + PaletteSize((LPSTR)&bi->bmiHeader));
	delete[] bi;

	Num = GetDIBits(hDC, hBitmap, 0, BitmapInfo->bmiHeader.biHeight, 
		BitmapBuf + BitmapInfo->bmiHeader.biSize + PaletteSize((LPSTR)&BitmapInfo->bmiHeader), BitmapInfo, DIB_RGB_COLORS);
	ReleaseDC(NULL, hDC);
	if ( Num == 0 ) {
		delete[] BitmapBuf;
		return 0;
	}

	*Buf = BitmapBuf;
	return Length;
}

HBITMAP GetBitMap(byte *Buf, size_t Size)
{
	PBITMAPINFO bi = (PBITMAPINFO) Buf;
	if ( Size < sizeof BITMAPINFOHEADER || 
		 Size < ( bi->bmiHeader.biSize + PaletteSize((LPSTR)&bi->bmiHeader) + bi->bmiHeader.biSizeImage) )
		 return NULL;

	HDC hDC = GetDC(NULL);
	HBITMAP hBitMap = CreateDIBitmap(hDC, &bi->bmiHeader, CBM_INIT, Buf + bi->bmiHeader.biSize + PaletteSize((LPSTR)&bi->bmiHeader),
									bi, DIB_RGB_COLORS);
	ReleaseDC(NULL, hDC);

	return hBitMap;
}

struct IconPack {
	DWORD xHotspot;
	DWORD yHotspot;
	size_t ColorSize;
	size_t MaskSize;
	// byte ColorBitMap[]
	// byte MaskBitMap[]
};


size_t Hicon2Bytes(const HICON hIcon, byte *Buf, size_t BufSize)
{
	ICONINFO IconInfo;
	BOOL rc = GetIconInfo(hIcon, &IconInfo);
	if ( !rc ) return 0;

	byte *ColorBuf;
	size_t ColorSize = 0;
	if ( IconInfo.hbmColor != NULL ) {
		ColorSize = GetBitMapBuffer(IconInfo.hbmColor, &ColorBuf);
		if ( ColorSize == 0 ) return 0;
	}

	byte *MaskBuf;
	size_t MaskSize = 0;
	if ( IconInfo.hbmMask != NULL ) {
		MaskSize = GetBitMapBuffer(IconInfo.hbmMask, &MaskBuf);
		if ( MaskSize == 0 ) return 0;
	}

	size_t Size = sizeof IconPack + ColorSize + MaskSize;
	if ( Size > BufSize ) return 0;

	IconPack *Pack = (IconPack *) Buf;
	Pack->xHotspot = IconInfo.xHotspot;
	Pack->yHotspot = IconInfo.yHotspot;
	Pack->ColorSize = ColorSize;
	Pack->MaskSize = MaskSize;
	memcpy(Buf + sizeof IconPack, ColorBuf, ColorSize);
	memcpy(Buf + sizeof IconPack + ColorSize, MaskBuf, MaskSize);

	return Size;
}

HICON Bytes2Hicon(byte *Buf, const size_t BufSize)
{
	IconPack *Pack = (IconPack *) Buf;
	if ( BufSize < sizeof IconPack || BufSize < ( sizeof IconPack + Pack->ColorSize + Pack->MaskSize ) )
		return NULL;

	ICONINFO IconInfo;
	IconInfo.fIcon = TRUE;
	IconInfo.xHotspot = Pack->xHotspot;
	IconInfo.yHotspot = Pack->yHotspot;
	IconInfo.hbmColor = GetBitMap(Buf + sizeof IconPack, Pack->ColorSize);
	IconInfo.hbmMask = GetBitMap(Buf + sizeof IconPack + Pack->ColorSize, Pack->MaskSize);

	HICON hIcon = CreateIconIndirect(&IconInfo);
	if ( IconInfo.hbmColor != NULL ) DeleteObject(IconInfo.hbmColor);
	if ( IconInfo.hbmMask != NULL ) DeleteObject(IconInfo.hbmMask);

	return hIcon;
}

}; // namespace commonlib {

