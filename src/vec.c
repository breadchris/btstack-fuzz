#include "vec.h"

/*
 * ========================================================
 *
 *                      IMPLEMENTATION
 *
 * ========================================================
 */
inline void* vec_new(size_t size) {
    return vec_new_cap(size, 1);
}


inline void* vec_new_cap(size_t size, size_t nitems) {
    void *vec = VEC_CALLOC(1, _vec_hdr_size + size * nitems);
    if (vec == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    vec = (char *) vec + _vec_hdr_size;

    _vec_hdr_cap(vec) = nitems;
    _vec_hdr_len(vec) = 0;
    _vec_hdr_item_size(vec) = size;

    return vec;
}


inline void* vec_dup(void *vec) {
    void *dup = VEC_MALLOC(_vec_hdr_size + _vec_hdr_cap(vec) * _vec_hdr_item_size(vec));
    if (dup == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    dup = (char *) dup + _vec_hdr_size;

    memcpy(_vec_hdr_addr(dup), _vec_hdr_addr(vec), _vec_total_size(vec));

    return dup;
}


inline void vec_free(void *vec) {
    VEC_FREE(_vec_hdr_addr(vec));
}


inline size_t vec_cap(void *vec) {
    return _vec_hdr_cap(vec);
}


inline size_t vec_len(void *vec) {
    return _vec_hdr_len(vec);
}


inline size_t vec_size(void *vec) {
    return vec_len(vec);
}


inline bool vec_is_empty(void *vec) {
    return _vec_hdr_len(vec) == 0 ? 1 : 0;
}


inline void vec_clear(void *vec) {
    _vec_hdr_len(vec) = 0;
}


inline void vec_pop(void *vec) {
    if (_vec_hdr_len(vec) > 0) {
        --_vec_hdr_len(vec);
    }
}


inline void vec_remove(void *vec, size_t index) {
    if (_vec_hdr_len(vec) > 0 && index < _vec_hdr_len(vec)) {
        memmove(
            (char *) vec + index * _vec_hdr_item_size(vec),
            (char *) vec + (index + 1) * _vec_hdr_item_size(vec),
            _vec_hdr_item_size(vec) * (_vec_hdr_len(vec) - (index + 1))
        );

        --_vec_hdr_len(vec);
    }
}
