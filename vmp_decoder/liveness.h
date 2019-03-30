
#ifdef __cplusplus
extern "C" {
#endif

#ifndef __liveness_h__
#define __liveness_h__

    struct liveness;

    struct liveness_set;

    struct liveness *liveness_create();

    int liveness_destroy(struct liveness *mod);

    int liveness_run(struct liveness *mod);

    int liveness_init_inout(struct liveness *mod);

    int liveness_set_alloc(struct liveness, char *key, int len);

    int liveness_inst_init(struct liveness_set *set);
    int liveness_inst_def_add(struct liveness_set *set, char *key, int len);
    int liveness_inst_use_add(struct liveness_set *set, char *key, int len);

    int liveness_defs_init(struct liveness_set *defs_set);
    int liveness_defs_add(struct liveness_set *defs_set);

    int liveness_uses_init(struct liveness_set *uses_set);
    int liveness_uses_add(struct liveness_set *uses_set);


#endif

#ifdef __cplusplus
}
#endif
