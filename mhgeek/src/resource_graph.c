#include "resource_graph.h"
#include "board_identity.h"
#include "event_config_store.h"
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int attach_object(cJSON *parent, const char *key, cJSON **child)
{
    if (!child || !*child || !cJSON_AddItemToObject(parent, key, *child))
        return 0;
    *child = NULL;
    return 1;
}

static int attach_array(cJSON *parent, cJSON **child)
{
    if (!child || !*child || !cJSON_AddItemToArray(parent, *child))
        return 0;
    *child = NULL;
    return 1;
}

struct graph_pos {
    double x;
    double y;
    double width;
    double height;
};

struct graph_pair_layout {
    struct graph_pos trigger;
    struct graph_pos action;
};

/* One vertical lane of nine slots. Each slot has its present and absent
 * branches stacked, with a larger gap before the next slot. The paired
 * variable and Action cards stay side by side at the same height. */
static struct graph_pair_layout graph_pair_layout(enum mhg_presence_slot slot,
                                                  bool present)
{
    enum {
        CARD_HEIGHT = 164,
        TRIGGER_WIDTH = 444,
        ACTION_WIDTH = 684,
        PAIR_GAP_X = 26,
        PAIR_PITCH_Y = 216,
        SLOT_GAP_Y = 64
    };
    double y = (double)slot * (2 * PAIR_PITCH_Y + SLOT_GAP_Y) +
               (present ? 0.0 : (double)PAIR_PITCH_Y);
    struct graph_pair_layout layout = {
        .trigger = {0.0, y, TRIGGER_WIDTH, CARD_HEIGHT},
        .action = {TRIGGER_WIDTH + PAIR_GAP_X, y, ACTION_WIDTH, CARD_HEIGHT}};

    return layout;
}

static int add_pos(cJSON *owner_object, const struct graph_pos *layout)
{
    cJSON *pos = cJSON_CreateObject();
    int result = pos && cJSON_AddNumberToObject(pos, "x", layout->x) &&
                 cJSON_AddNumberToObject(pos, "y", layout->y) &&
                 cJSON_AddNumberToObject(pos, "width", layout->width) &&
                 cJSON_AddNumberToObject(pos, "height", layout->height) &&
                 attach_object(owner_object, "pos", &pos);

    cJSON_Delete(pos);
    return result;
}

static cJSON *build_base_graph(const struct mhg_resource_lan_config *config,
                               const struct mhg_resource_record *record, bool enabled,
                               struct mhg_error *error)
{
    cJSON *graph = cJSON_CreateObject();
    cJSON *nodes = cJSON_CreateArray();
    cJSON *cfg = cJSON_CreateObject();
    cJSON *user_data = cJSON_CreateObject();
    cJSON *transform = cJSON_CreateObject();
    size_t index;

    if (!graph || !nodes || !cfg || !user_data || !transform)
        goto fail;
    for (index = 0u; index < MHG_RESOURCE_VARIABLE_COUNT; ++index) {
        bool present = (index % 2u) == 0u;
        enum mhg_presence_slot slot = (enum mhg_presence_slot)(index / 2u);
        const struct mhg_secret_buf *variable =
            mhg_resource_variable(record, slot, present);
        char trigger[32];
        char action[32];
        char output[48];
        struct graph_pair_layout layout = graph_pair_layout(slot, present);
        cJSON *trigger_node = cJSON_CreateObject();
        cJSON *action_node = cJSON_CreateObject();
        cJSON *trigger_cfg = cJSON_CreateObject();
        cJSON *action_cfg = cJSON_CreateObject();
        cJSON *trigger_props = cJSON_CreateObject();
        cJSON *action_props = cJSON_CreateObject();
        cJSON *inputs = cJSON_CreateObject();
        cJSON *outputs = cJSON_CreateObject();
        cJSON *action_outputs = cJSON_CreateObject();
        cJSON *output_list = cJSON_CreateArray();
        cJSON *empty_output = cJSON_CreateArray();
        cJSON *action_inputs = cJSON_CreateObject();
        cJSON *ins = cJSON_CreateArray();
        cJSON *pin = cJSON_CreateObject();
        cJSON *output_value = NULL;

        if (!trigger_node || !action_node || !trigger_cfg || !action_cfg ||
            !trigger_props || !action_props || !inputs || !outputs || !action_outputs ||
            !output_list || !empty_output || !action_inputs || !ins || !pin)
            goto node_fail;
        if (mhg_resource_node_id(slot, present, true, trigger, sizeof(trigger)) != 0 ||
            mhg_resource_node_id(slot, present, false, action, sizeof(action)) != 0)
            goto node_fail;
        snprintf(output, sizeof(output), "%s.trigger", action);
        output_value = cJSON_CreateString(output);
        if (!cJSON_AddNullToObject(action_inputs, "trigger") ||
            !attach_array(output_list, &output_value) ||
            !attach_object(outputs, "output", &output_list) ||
            !attach_object(action_outputs, "output", &empty_output) ||
            !cJSON_AddStringToObject(trigger_cfg, "name", "varChange") ||
            !cJSON_AddNumberToObject(trigger_cfg, "version", 1.0) ||
            !add_pos(trigger_cfg, &layout.trigger) ||
            !cJSON_AddStringToObject(action_cfg, "name", "deviceOutput") ||
            !cJSON_AddNumberToObject(action_cfg, "version", 1.0) ||
            !cJSON_AddStringToObject(action_cfg, "urn", config->urn) ||
            !add_pos(action_cfg, &layout.action) ||
            !cJSON_AddStringToObject(trigger_node, "id", trigger) ||
            !cJSON_AddStringToObject(trigger_node, "type", "varChange") ||
            !cJSON_AddStringToObject(trigger_props, "scope",
                                     (const char *)record->scope.data) ||
            !cJSON_AddStringToObject(trigger_props, "id",
                                     (const char *)variable->data) ||
            !cJSON_AddStringToObject(trigger_props, "varType", "number") ||
            !cJSON_AddBoolToObject(trigger_props, "preload", false) ||
            !cJSON_AddStringToObject(trigger_props, "operator", "=") ||
            !cJSON_AddNumberToObject(trigger_props, "v1", 1.0) ||
            !cJSON_AddStringToObject(action_node, "id", action) ||
            !cJSON_AddStringToObject(action_node, "type", "deviceOutput") ||
            !cJSON_AddStringToObject(action_props, "did", config->target_did) ||
            !cJSON_AddNumberToObject(action_props, "siid", (double)config->siid) ||
            !cJSON_AddNumberToObject(action_props, "aiid", (double)config->aiid) ||
            !cJSON_AddNumberToObject(pin, "piid", (double)config->piid) ||
            !cJSON_AddStringToObject(pin, "value", config->texts[index]) ||
            !attach_array(ins, &pin) || !attach_object(action_props, "ins", &ins) ||
            !attach_object(trigger_node, "cfg", &trigger_cfg) ||
            !attach_object(trigger_node, "props", &trigger_props) ||
            !attach_object(trigger_node, "inputs", &inputs) ||
            !attach_object(trigger_node, "outputs", &outputs) ||
            !attach_object(action_node, "cfg", &action_cfg) ||
            !attach_object(action_node, "props", &action_props) ||
            !attach_object(action_node, "inputs", &action_inputs) ||
            !attach_object(action_node, "outputs", &action_outputs) ||
            !attach_array(nodes, &trigger_node) || !attach_array(nodes, &action_node))
            goto node_fail;
        continue;
    node_fail:
        cJSON_Delete(output_value);
        cJSON_Delete(pin);
        cJSON_Delete(ins);
        cJSON_Delete(action_inputs);
        cJSON_Delete(empty_output);
        cJSON_Delete(output_list);
        cJSON_Delete(action_outputs);
        cJSON_Delete(outputs);
        cJSON_Delete(inputs);
        cJSON_Delete(action_props);
        cJSON_Delete(trigger_props);
        cJSON_Delete(action_cfg);
        cJSON_Delete(trigger_cfg);
        cJSON_Delete(trigger_node);
        cJSON_Delete(action_node);
        goto fail;
    }
    if (!cJSON_AddNumberToObject(transform, "x", 0.0) ||
        !cJSON_AddNumberToObject(transform, "y", 0.0) ||
        !cJSON_AddNumberToObject(transform, "scale", 1.0) ||
        !cJSON_AddNumberToObject(transform, "rotate", 0.0))
        goto fail;
    {
        char name[64];

        /* Display name only: 视觉空间传感器(<mac>); ids stay the stable ones. */
        char identity[32];

        if (mhg_board_identity_text(identity, sizeof(identity)) != 0) {
            mhg_errorf(error, ENODEV, "board identity is unavailable");
            goto fail;
        }
        snprintf(name, sizeof(name), "AInice视觉空间传感器 (%s)", identity);
        if (!cJSON_AddStringToObject(user_data, "name", name) ||
            !attach_object(user_data, "transform", &transform) ||
            !cJSON_AddNumberToObject(user_data, "lastUpdateTime", 0.0) ||
            !cJSON_AddNumberToObject(user_data, "version", 0.0) ||
            !cJSON_AddStringToObject(cfg, "id", (const char *)record->graph_id.data) ||
            !cJSON_AddBoolToObject(cfg, "enable", enabled) ||
            !cJSON_AddStringToObject(cfg, "uiType", "test") ||
            !attach_object(cfg, "userData", &user_data) ||
            !cJSON_AddStringToObject(graph, "id",
                                     (const char *)record->graph_id.data) ||
            !attach_object(graph, "cfg", &cfg) ||
            !attach_object(graph, "nodes", &nodes))
            goto fail;
    }
    return graph;

fail:
    cJSON_Delete(transform);
    cJSON_Delete(user_data);
    cJSON_Delete(cfg);
    cJSON_Delete(nodes);
    cJSON_Delete(graph);
    return NULL;
}

/* The graph starts with the verified trigger and Action card shapes, then
 * routes both directions through a global-state guard before writing the
 * output variable and emitting the corresponding virtual event. */
static int replace_number(cJSON *object, const char *key, double value)
{
    cJSON *item = cJSON_CreateNumber(value);

    if (!item)
        return -1;
    cJSON_DeleteItemFromObjectCaseSensitive(object, key);
    if (!cJSON_AddItemToObject(object, key, item)) {
        cJSON_Delete(item);
        return -1;
    }
    return 0;
}

static int replace_output(cJSON *node, const char *target)
{
    cJSON *outputs = cJSON_GetObjectItemCaseSensitive(node, "outputs");
    cJSON *list = cJSON_CreateArray();
    cJSON *value = target ? cJSON_CreateString(target) : NULL;
    int status = -1;

    if (!cJSON_IsObject(outputs) || !list || (target && !value))
        goto done;
    if (value && !attach_array(list, &value))
        goto done;
    /* The editor positions edges by Object.keys(outputs), in connector order. */
    if (!cJSON_ReplaceItemInObjectCaseSensitive(outputs, "output", list))
        goto done;
    list = NULL;
    status = 0;
done:
    cJSON_Delete(value);
    cJSON_Delete(list);
    return status;
}

static int replace_gate_output(cJSON *node, const char *first, const char *second)
{
    cJSON *outputs = cJSON_GetObjectItemCaseSensitive(node, "outputs");
    cJSON *list = cJSON_CreateArray();
    cJSON *first_value = first ? cJSON_CreateString(first) : NULL;
    cJSON *second_value = second ? cJSON_CreateString(second) : NULL;
    int status = -1;

    if (!cJSON_IsObject(outputs) || !list || (first && !first_value) ||
        (second && !second_value))
        goto done;
    if ((first_value && !attach_array(list, &first_value)) ||
        (second_value && !attach_array(list, &second_value)))
        goto done;
    /* Keep output before output2: the hub editor uses member order. */
    if (!cJSON_ReplaceItemInObjectCaseSensitive(outputs, "output", list))
        goto done;
    list = NULL;
    status = 0;
done:
    cJSON_Delete(first_value);
    cJSON_Delete(second_value);
    cJSON_Delete(list);
    return status;
}

static int replace_pos(cJSON *node, const struct graph_pos *pos)
{
    cJSON *cfg = cJSON_GetObjectItemCaseSensitive(node, "cfg");

    if (!cJSON_IsObject(cfg))
        return -1;
    cJSON_DeleteItemFromObjectCaseSensitive(cfg, "pos");
    return add_pos(cfg, pos) ? 0 : -1;
}

static cJSON *build_delay(const char *id, const char *target,
                          const struct graph_pos *pos, double seconds)
{
    static const char skeleton[] =
        "{\"type\":\"statusLast\",\"cfg\":{\"name\":\"statusLast\","
        "\"version\":1},\"props\":{},\"inputs\":{\"input\":null},"
        "\"outputs\":{\"output\":[]}}";
    cJSON *node = cJSON_Parse(skeleton);
    cJSON *cfg;
    cJSON *props;
    double milliseconds = seconds * 1000.0;
    uint64_t ms;

    if (!node || !mhg_event_config_seconds_valid(seconds))
        goto fail;
    ms = (uint64_t)milliseconds;
    cfg = cJSON_GetObjectItemCaseSensitive(node, "cfg");
    props = cJSON_GetObjectItemCaseSensitive(node, "props");
    if (!cJSON_AddStringToObject(node, "id", id) ||
        !cJSON_AddNumberToObject(cfg, "value", seconds) ||
        !cJSON_AddStringToObject(cfg, "unit", "s") || !add_pos(cfg, pos) ||
        !cJSON_AddNumberToObject(props, "timeout", (double)ms) ||
        replace_output(node, target) != 0)
        goto fail;
    return node;
fail:
    cJSON_Delete(node);
    return NULL;
}

static cJSON *build_gate(const char *id, const char *global_id, bool present,
                         const char *setter_id, const char *action_id,
                         const struct graph_pos *pos)
{
    static const char skeleton[] = "{\"type\":\"varGet\",\"cfg\":{\"name\":\"varGet\","
                                   "\"version\":1},\"props\":{\"scope\":\"global\","
                                   "\"varType\":\"number\",\"operator\":\"!=\"},"
                                   "\"inputs\":{\"input\":null},\"outputs\":{"
                                   "\"output\":[],\"output2\":[]}}";
    cJSON *node = cJSON_Parse(skeleton);
    cJSON *cfg;
    cJSON *props;
    char setter_target[48];
    char action_target[48];

    if (!node)
        return NULL;
    cfg = cJSON_GetObjectItemCaseSensitive(node, "cfg");
    props = cJSON_GetObjectItemCaseSensitive(node, "props");
    snprintf(setter_target, sizeof(setter_target), "%s.input", setter_id);
    snprintf(action_target, sizeof(action_target), "%s.trigger", action_id);
    if (!cJSON_AddStringToObject(node, "id", id) ||
        !cJSON_AddStringToObject(props, "id", global_id) ||
        !cJSON_AddNumberToObject(props, "v1", present ? 1.0 : 0.0) ||
        !add_pos(cfg, pos) ||
        replace_gate_output(node, setter_target, action_target) != 0) {
        cJSON_Delete(node);
        return NULL;
    }
    return node;
}

static cJSON *build_setter(const char *id, const char *global_id, bool present,
                           const struct graph_pos *pos)
{
    static const char skeleton[] =
        "{\"type\":\"varSetNumber\",\"cfg\":{\"name\":\"varSetNumber\","
        "\"version\":1},\"props\":{\"scope\":\"global\"},"
        "\"inputs\":{\"input\":null},\"outputs\":{\"output\":[]}}";
    cJSON *node = cJSON_Parse(skeleton);
    cJSON *cfg;
    cJSON *props;
    cJSON *elements = cJSON_CreateArray();
    cJSON *element = cJSON_CreateObject();

    if (!node || !elements || !element)
        goto fail;
    cfg = cJSON_GetObjectItemCaseSensitive(node, "cfg");
    props = cJSON_GetObjectItemCaseSensitive(node, "props");
    if (!cJSON_AddStringToObject(node, "id", id) || !add_pos(cfg, pos) ||
        !cJSON_AddStringToObject(props, "id", global_id) ||
        !cJSON_AddStringToObject(element, "type", "const") ||
        !cJSON_AddStringToObject(element, "value", present ? "1" : "0") ||
        !attach_array(elements, &element) ||
        !attach_object(props, "elements", &elements))
        goto fail;
    return node;
fail:
    cJSON_Delete(element);
    cJSON_Delete(elements);
    cJSON_Delete(node);
    return NULL;
}

static cJSON *build_note(const struct mhg_resource_record *record)
{
    static const char template[] =
        "{\"type\":\"nop\",\"cfg\":{\"name\":\"nop\",\"version\":0,"
        "\"background\":\"#FFD966\",\"contents\":["
        "{\"insert\":\"说明\",\"attributes\":{\"bold\":true}},"
        "{\"insert\":\"\\n\",\"attributes\":{\"header\":3}},"
        "{\"insert\":"
        "\"本自动化由插件自动生成并维护。请勿修改或删除卡片、接线及关联变量，也请勿"
        "禁用本自动化。\\n如需调整事件名称或无人持续时间，请在插件中修改，插件会自动同步至"
        "本自动化。\\n如需创建自定义自动化，可使用全局变量的“变量值更新”卡片作为触发条件，"
        "使用“查询变量值”卡片判断状态。\\n变量值为 1 表示有人，为 0 表示无人。\\n\"}],"
        "\"pos\":{\"x\":480,\"y\":-382,\"width\":740,\"height\":216}},"
        "\"props\":{},\"inputs\":{},\"outputs\":{\"output\":[]}}";
    char id[96];
    snprintf(id, sizeof(id), "%sNote", (const char *)record->graph_id.data);
    cJSON *node = cJSON_Parse(template);
    if (!node || !cJSON_AddStringToObject(node, "id", id)) {
        cJSON_Delete(node);
        return NULL;
    }
    return node;
}
cJSON *mhg_resource_graph_build(const struct mhg_resource_lan_config *config,
                                const struct mhg_resource_record *record, bool enabled,
                                struct mhg_error *error)
{
    cJSON *graph;
    cJSON *nodes;
    cJSON *note = NULL;
    size_t index;

    if (!config || !record || !config->target_did || !config->target_model ||
        !config->urn || !config->texts || !config->absent_seconds)
        return NULL;
    for (size_t i = 0; i < MHG_PRESENCE_SLOT_COUNT; ++i)
        if (!mhg_event_config_seconds_valid(config->absent_seconds[i]))
            return NULL;
    for (size_t i = 0; i < MHG_RESOURCE_VARIABLE_COUNT; ++i)
        if (!config->texts[i])
            return NULL;
    if ((!record->target_did.data || !record->target_model.data ||
         !record->action_urn.data ||
         strcmp((const char *)record->target_did.data, config->target_did) != 0 ||
         strcmp((const char *)record->target_model.data, config->target_model) != 0 ||
         strcmp((const char *)record->action_urn.data, config->urn) != 0 ||
         record->action_siid != config->siid || record->action_aiid != config->aiid ||
         record->action_piid != config->piid)) {
        mhg_errorf(error, EPROTO, "managed graph target/action binding differs");
        return NULL;
    }
    graph = build_base_graph(config, record, enabled, error);
    if (!graph)
        return NULL;
    nodes = cJSON_GetObjectItemCaseSensitive(graph, "nodes");
    for (index = 0u; index < MHG_RESOURCE_VARIABLE_COUNT; ++index) {
        bool present = (index % 2u) == 0u;
        size_t slot = index / 2u;
        cJSON *trigger = cJSON_GetArrayItem(nodes, (int)(2u * index));
        cJSON *action = cJSON_GetArrayItem(nodes, (int)(2u * index + 1u));
        cJSON *props = cJSON_GetObjectItemCaseSensitive(trigger, "props");
        const struct mhg_secret_buf *global =
            mhg_resource_global_variable(record, (enum mhg_presence_slot)slot);
        /* Leave a 64px clear gap between one slot's absent Action and the
         * next slot's elevated present setter. */
        double row_y = (double)slot * 672.0;
        struct graph_pos trigger_pos;
        struct graph_pos action_pos;
        struct graph_pos gate_pos;
        struct graph_pos delay_pos = {468.0, row_y + 272.5, 288.0, 119.0};
        struct graph_pos setter_pos;
        char action_id[32];
        char delay_id[32];
        char setter_id[32];
        char gate_id[32];
        char target[48];
        cJSON *delay = NULL;
        cJSON *gate = NULL;
        cJSON *setter = NULL;

        if (!global || !global->data ||
            mhg_resource_node_id((enum mhg_presence_slot)slot, present, false,
                                 action_id, sizeof(action_id)) != 0)
            goto fail;
        snprintf(delay_id, sizeof(delay_id), "slot%zuAbsentDelay", slot);
        snprintf(setter_id, sizeof(setter_id), "slot%zu%sSet", slot,
                 present ? "Present" : "Absent");
        snprintf(gate_id, sizeof(gate_id), "slot%zu%sGate", slot,
                 present ? "Present" : "Absent");
        if (present) {
            trigger_pos = (struct graph_pos){0.0, row_y + 6.0, 444.0, 152.0};
            gate_pos = (struct graph_pos){606.0, row_y + 22.0, 532.0, 120.0};
            setter_pos = (struct graph_pos){1217.0, row_y - 99.0, 740.0, 112.0};
            action_pos = (struct graph_pos){1218.0, row_y + 29.0, 684.0, 164.0};
            snprintf(target, sizeof(target), "%s.input", gate_id);
        } else {
            trigger_pos = (struct graph_pos){0.0, row_y + 265.0, 444.0, 152.0};
            gate_pos = (struct graph_pos){791.0, row_y + 272.0, 532.0, 120.0};
            setter_pos = (struct graph_pos){1420.0, row_y + 220.0, 740.0, 112.0};
            action_pos = (struct graph_pos){1421.0, row_y + 346.0, 684.0, 164.0};
            snprintf(target, sizeof(target), "%s.input", delay_id);
        }
        trigger_pos.x += MHG_GRAPH_LEFT;
        action_pos.x += MHG_GRAPH_LEFT;
        gate_pos.x += MHG_GRAPH_LEFT;
        delay_pos.x += MHG_GRAPH_LEFT;
        setter_pos.x += MHG_GRAPH_LEFT;
        if (!cJSON_IsObject(props) ||
            replace_number(props, "v1", present ? 1.0 : 0.0) != 0 ||
            replace_pos(trigger, &trigger_pos) != 0 ||
            replace_output(trigger, target) != 0 ||
            replace_pos(action, &action_pos) != 0 || replace_output(action, NULL) != 0)
            goto fail;
        if (!present) {
            snprintf(target, sizeof(target), "%s.input", gate_id);
            delay =
                build_delay(delay_id, target, &delay_pos, config->absent_seconds[slot]);
            if (!delay || !attach_array(nodes, &delay)) {
                cJSON_Delete(delay);
                goto fail;
            }
        }
        gate = build_gate(gate_id, (const char *)global->data, present, setter_id,
                          action_id, &gate_pos);
        if (!gate || !attach_array(nodes, &gate)) {
            cJSON_Delete(gate);
            goto fail;
        }
        setter =
            build_setter(setter_id, (const char *)global->data, present, &setter_pos);
        if (!setter || !attach_array(nodes, &setter)) {
            cJSON_Delete(setter);
            goto fail;
        }
    }
    note = build_note(record);
    if (!note || !attach_array(nodes, &note))
        goto fail;
    return graph;
fail:
    cJSON_Delete(note);
    cJSON_Delete(graph);
    mhg_errorf(error, EPROTO, "managed graph construction failed");
    return NULL;
}

static const cJSON *node_for_id(const cJSON *nodes, const char *id)
{
    const cJSON *node, *found = NULL;
    cJSON_ArrayForEach(node, nodes)
    {
        const cJSON *nid = cJSON_GetObjectItemCaseSensitive(node, "id");
        if (cJSON_IsString(nid) && !strcmp(nid->valuestring, id)) {
            if (found)
                return NULL;
            found = node;
        }
    }
    return found;
}
static bool is_note(const cJSON *node)
{
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(node, "type");
    return cJSON_IsString(type) && !strcmp(type->valuestring, "nop");
}
static cJSON *normalized_node(const cJSON *node, bool functional_only)
{
    cJSON *copy = cJSON_Duplicate(node, 1);
    cJSON *cfg = cJSON_GetObjectItemCaseSensitive(copy, "cfg");
    const cJSON *version = cJSON_GetObjectItemCaseSensitive(cfg, "version");
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(copy, "type");
    /* The installed editor rewrites card version 1 to 0 on save. */
    if (!cJSON_IsNumber(version) ||
        (version->valuedouble != 0 && version->valuedouble != 1) ||
        replace_number(cfg, "version", 1))
        goto fail;
    if (cJSON_IsString(type) && !strcmp(type->valuestring, "varSetNumber")) {
        cJSON *pos = cJSON_GetObjectItemCaseSensitive(cfg, "pos");
        const cJSON *height = cJSON_GetObjectItemCaseSensitive(pos, "exprHeight");
        /* The editor adds this measured expression-row height. */
        if (height && (!cJSON_IsNumber(height) || height->valuedouble != 30))
            goto fail;
        cJSON_DeleteItemFromObjectCaseSensitive(pos, "exprHeight");
    }
    if (functional_only)
        cJSON_DeleteItemFromObjectCaseSensitive(cfg, "pos");
    return copy;
fail:
    cJSON_Delete(copy);
    return NULL;
}
/* Compare the generated contract, allowing unrelated response metadata.
 * Port objects and arrays stay closed: added wiring changes behavior. */
static bool managed_fields_match(const cJSON *expected, const cJSON *actual,
                                 bool closed)
{
    if (cJSON_IsObject(expected)) {
        if (!cJSON_IsObject(actual))
            return false;
        if (closed && cJSON_GetArraySize(expected) != cJSON_GetArraySize(actual))
            return false;
        const cJSON *field;
        cJSON_ArrayForEach(field, expected)
        {
            const cJSON *other =
                cJSON_GetObjectItemCaseSensitive(actual, field->string);
            bool ports =
                !strcmp(field->string, "outputs") || !strcmp(field->string, "inputs");
            if (!other || !managed_fields_match(field, other, ports))
                return false;
        }
        return true;
    }
    if (cJSON_IsArray(expected)) {
        if (!cJSON_IsArray(actual) ||
            cJSON_GetArraySize(expected) != cJSON_GetArraySize(actual))
            return false;
        for (int i = 0; i < cJSON_GetArraySize(expected); ++i)
            if (!managed_fields_match(cJSON_GetArrayItem(expected, i),
                                      cJSON_GetArrayItem(actual, i), false))
                return false;
        return true;
    }
    return cJSON_Compare(expected, actual, 1);
}
bool mhg_resource_graph_nodes_match(const cJSON *desired, const cJSON *actual,
                                    bool functional_only)
{
    const cJSON *node;
    size_t count = 0, actual_count = 0;
    if (!cJSON_IsArray(desired) || !cJSON_IsArray(actual))
        return false;
    cJSON_ArrayForEach(node, desired)
    {
        if (functional_only && is_note(node))
            continue;
        ++count;
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(node, "id");
        if (!cJSON_IsString(id))
            return false;
        const cJSON *other = node_for_id(actual, id->valuestring);
        if (!other)
            return false;
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(node, "type");
        if (cJSON_IsString(type) && !strcmp(type->valuestring, "varGet")) {
            const cJSON *ports = cJSON_GetObjectItemCaseSensitive(other, "outputs");
            if (!ports || !ports->child || !ports->child->string ||
                strcmp(ports->child->string, "output") || !ports->child->next ||
                !ports->child->next->string ||
                strcmp(ports->child->next->string, "output2"))
                return false;
        }
        {
            cJSON *a = normalized_node(node, functional_only),
                  *b = normalized_node(other, functional_only);
            bool equal = a && b && managed_fields_match(a, b, false);
            cJSON_Delete(a);
            cJSON_Delete(b);
            if (!equal)
                return false;
        }
    }
    cJSON_ArrayForEach(node,
                       actual) if (!(functional_only && is_note(node)))++ actual_count;
    return count == actual_count;
}
int mhg_resource_graph_digest(const cJSON *nodes, char out[33])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0u;
    char *text = cJSON_PrintUnformatted(nodes);
    size_t index;
    int result = -1;

    if (!text)
        return -1;
    if (EVP_Digest(text, strlen(text), digest, &length, EVP_sha256(), NULL) == 1 &&
        length >= 16u) {
        for (index = 0u; index < 16u; ++index)
            snprintf(out + index * 2u, 3u, "%02x", digest[index]);
        result = 0;
    }
    OPENSSL_clear_free(text, strlen(text));
    return result;
}
