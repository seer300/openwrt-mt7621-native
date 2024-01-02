
#define Rotl(_x, _y) (((_x) << (_y)) | ((_x) >> (32 - (_y))))
#define getbyte(_x,_y) (((unsigned char *)&(_x))[_y])

#define ByteSub(_A) (ISbox[((unsigned int)_A) >> 24 & 0xFF] << 24 ^ \
                     ISbox[((unsigned int)_A) >> 16 & 0xFF] << 16 ^ \
                     ISbox[((unsigned int)_A) >>  8 & 0xFF] <<  8 ^ \
                     ISbox[((unsigned int)_A) & 0xFF])

#define L1(_B) ((_B) ^ Rotl(_B, 2) ^ Rotl(_B, 10) ^ Rotl(_B, 18) ^ Rotl(_B, 24))
#define L2(_B) ((_B) ^ Rotl(_B, 13) ^ Rotl(_B, 23))
