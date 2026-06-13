<template>
  <DataPanel
    :title="title"
    :subtitle="subtitle"
    :loading="loading"
    :show-skeleton="false"
    :error="error"
    :last-updated="lastUpdated"
    :show-refresh="showRefresh"
    :live-refresh="liveRefresh"
    :live-enabled="liveEnabled"
    :refresh-label="refreshLabel"
    :variant="variant"
    @update:liveEnabled="$emit('update:liveEnabled', $event)"
    @refresh="$emit('refresh')"
  >
    <v-row v-if="showTableControls" dense class="mb-3">
      <v-col v-if="searchEnabled" cols="12" md="6">
        <v-text-field
          v-model.trim="tableSearchQuery"
          :label="searchLabel"
          :placeholder="searchPlaceholder"
          prepend-inner-icon="mdi-magnify"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col
        v-for="definition in resolvedFilterDefinitions"
        :key="`filter-${definition.key}`"
        cols="12"
        sm="6"
        md="3"
      >
        <v-select
          v-model="tableFilterValues[definition.key]"
          :items="definition.items"
          :label="definition.label"
          item-title="label"
          item-value="value"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
    </v-row>
    <div class="entity-table-wrap mt-1">
      <v-data-table
        v-model:page="currentPage"
        v-model:expanded="expandedRowKeys"
        :headers="tableHeaders"
        :items="tableItems"
        item-value="__entityTableRowKey"
        :items-per-page="enablePagination ? safePageSize : -1"
        :items-per-page-options="itemsPerPageOptions"
        :hide-default-footer="!enablePagination || filteredRows.length <= safePageSize"
        :hide-no-data="loading"
        :show-expand="expandableRows"
        expand-strategy="single"
        density="comfortable"
        class="entity-data-table"
        mobile-breakpoint="960"
      >
        <template v-if="expandableRows" v-slot:[expandHeaderSlotName]>
          <span class="entity-data-table__expand-header" aria-hidden="true"></span>
        </template>

        <template
          v-if="expandableRows"
          v-slot:[expandItemSlotName]="{ internalItem, isExpanded, toggleExpand }"
        >
          <v-btn
            icon
            size="small"
            variant="text"
            color="info"
            class="entity-data-table__expand-button"
            :aria-label="isExpanded(internalItem) ? 'Collapse JSON view' : 'Expand JSON view'"
            @click.stop="toggleExpand(internalItem)"
          >
            <v-icon :icon="isExpanded(internalItem) ? 'mdi-chevron-down' : 'mdi-chevron-right'" />
          </v-btn>
        </template>

        <template
          v-for="column in normalizedColumns"
          :key="`slot-${column.key}`"
          v-slot:[column.itemSlotName]="slotProps"
        >
          <slot
            :name="`cell-${column.key}`"
            :item="slotProps.item"
            :value="resolveValue(slotProps.item, column)"
          >
            {{ formatValue(slotProps.item, column) }}
          </slot>
        </template>

        <template v-if="expandableRows" #expanded-row="{ columns, item }">
          <tr class="entity-data-table__expanded-row">
            <td :colspan="columns.length" class="entity-data-table__expanded-cell">
              <slot :item="item" :json="formatJson(item)" name="row-expanded">
                <div class="entity-json-panel">
                  <div class="entity-json-panel__label">Full row JSON</div>
                  <pre class="entity-json">{{ formatJson(item) }}</pre>
                </div>
              </slot>
            </td>
          </tr>
        </template>

        <template #no-data>
          <div class="entity-table-empty text-medium-emphasis text-center">
            {{ emptyText }}
          </div>
        </template>
      </v-data-table>
    </div>
  </DataPanel>
</template>

<script>
import DataPanel from "./DataPanel.vue";
import { matchesSearch, normalizeSearchText, uniqueSorted } from "../../utils/traffic";

function getByPath(item, path) {
  if (!item || !path) return "";
  if (!String(path).includes(".")) {
    return item[path];
  }
  return String(path)
    .split(".")
    .reduce((acc, key) => (acc && acc[key] !== undefined ? acc[key] : undefined), item);
}

export default {
  name: "EntityTablePanel",
  components: { DataPanel },
  props: {
    title: {
      type: String,
      required: true,
    },
    subtitle: {
      type: String,
      default: "",
    },
    rows: {
      type: Array,
      default: () => [],
    },
    columns: {
      type: Array,
      default: () => [],
    },
    loading: {
      type: Boolean,
      default: false,
    },
    error: {
      type: String,
      default: "",
    },
    emptyText: {
      type: String,
      default: "No data",
    },
    rowKey: {
      type: String,
      default: "id",
    },
    showRefresh: {
      type: Boolean,
      default: false,
    },
    liveRefresh: {
      type: Boolean,
      default: false,
    },
    liveEnabled: {
      type: Boolean,
      default: false,
    },
    refreshLabel: {
      type: String,
      default: "Refresh",
    },
    lastUpdated: {
      type: String,
      default: "",
    },
    enablePagination: {
      type: Boolean,
      default: true,
    },
    pageSize: {
      type: Number,
      default: 50,
    },
    variant: {
      type: String,
      default: "outlined",
    },
    expandableRows: {
      type: Boolean,
      default: false,
    },
    searchEnabled: {
      type: Boolean,
      default: false,
    },
    searchLabel: {
      type: String,
      default: "Search",
    },
    searchPlaceholder: {
      type: String,
      default: "Search rows",
    },
    searchFields: {
      type: Array,
      default: () => [],
    },
    filterDefinitions: {
      type: Array,
      default: () => [],
    },
  },
  emits: ["refresh", "update:liveEnabled"],
  data() {
    return {
      currentPage: 1,
      expandedRowKeys: [],
      tableSearchQuery: "",
      tableFilterValues: {},
    };
  },
  computed: {
    normalizedRows() {
      return Array.isArray(this.rows) ? this.rows : [];
    },
    normalizedColumns() {
      return Array.isArray(this.columns)
        ? this.columns
          .filter((column) => column && column.key)
          .map((column) => ({
            ...column,
            itemSlotName: `item.${column.key}`,
          }))
        : [];
    },
    safePageSize() {
      const parsed = Number(this.pageSize);
      if (!Number.isFinite(parsed) || parsed <= 0) return 50;
      return Math.floor(parsed);
    },
    showTableControls() {
      return this.searchEnabled || this.resolvedFilterDefinitions.length > 0;
    },
    resolvedSearchFields() {
      const explicitFields = Array.isArray(this.searchFields) ? this.searchFields.filter(Boolean) : [];
      if (explicitFields.length) return explicitFields;
      return this.normalizedColumns
        .map((column) => column.searchField || column.key)
        .filter((key) => key && key !== "actions" && key !== "data-table-expand");
    },
    resolvedFilterDefinitions() {
      if (!Array.isArray(this.filterDefinitions)) return [];
      return this.filterDefinitions
        .filter((definition) => definition && definition.key)
        .map((definition) => ({
          ...definition,
          items: this.buildFilterItems(definition),
        }));
    },
    filteredRows() {
      const query = String(this.tableSearchQuery || "").trim();
      const activeFilters = this.resolvedFilterDefinitions.filter((definition) => {
        return normalizeSearchText(this.tableFilterValues[definition.key]);
      });
      return this.normalizedRows.filter((item) => {
        if (query && !matchesSearch(query, this.resolveSearchValues(item))) {
          return false;
        }
        return activeFilters.every((definition) => this.matchesFilterDefinition(item, definition));
      });
    },
    pageCount() {
      return Math.max(1, Math.ceil(this.filteredRows.length / this.safePageSize));
    },
    itemsPerPageOptions() {
      const values = [...new Set([this.safePageSize, this.safePageSize * 2, this.safePageSize * 4])]
        .filter((value) => Number.isFinite(value) && value > 0)
        .sort((left, right) => left - right);
      return [
        ...values.map((value) => ({ title: String(value), value })),
        { title: "All", value: -1 },
      ];
    },
    tableHeaders() {
      const headers = this.normalizedColumns.map((column) => ({
        key: column.key,
        title: column.label || column.key,
        sortable: column.sortable !== false && column.key !== "actions",
        align: column.align || "start",
        width: column.width,
        fixed: column.fixed,
      }));
      if (this.expandableRows) {
        headers.unshift({
          key: "data-table-expand",
          title: "",
          sortable: false,
          width: 48,
        });
      }
      return headers;
    },
    tableItems() {
      return this.filteredRows.map((item, index) => ({
        ...(item && typeof item === "object" ? item : { value: item }),
        __entityTableRowKey: this.resolveRowKey(item, index),
      }));
    },
    tableItemKeys() {
      return new Set(this.tableItems.map((item) => String(item.__entityTableRowKey)));
    },
    expandHeaderSlotName() {
      return "header.data-table-expand";
    },
    expandItemSlotName() {
      return "item.data-table-expand";
    },
  },
  watch: {
    rows() {
      this.syncTableFilterValues();
      if (this.currentPage > this.pageCount) {
        this.currentPage = this.pageCount;
      }
      this.syncExpandedRows();
    },
    pageSize() {
      this.currentPage = 1;
      this.expandedRowKeys = [];
    },
    filterDefinitions: {
      deep: true,
      handler() {
        this.syncTableFilterValues();
      },
    },
    tableSearchQuery() {
      this.currentPage = 1;
      this.syncExpandedRows();
    },
    tableFilterValues: {
      deep: true,
      handler() {
        this.currentPage = 1;
        this.syncExpandedRows();
      },
    },
  },
  created() {
    this.syncTableFilterValues();
  },
  methods: {
    resolveRowKey(item, index) {
      const explicit = getByPath(item, this.rowKey);
      if (explicit !== undefined && explicit !== null && explicit !== "") {
        return String(explicit);
      }
      if (item && item.id !== undefined && item.id !== null && item.id !== "") {
        return String(item.id);
      }
      if (item && item.key !== undefined && item.key !== null && item.key !== "") {
        return String(item.key);
      }
      if (item && item.flow_key) {
        return String(item.flow_key);
      }
      return `row-${index}`;
    },
    resolveFieldValue(item, field) {
      if (typeof field === "function") {
        return field(item);
      }
      if (field && typeof field === "object") {
        if (typeof field.value === "function") {
          return field.value(item);
        }
        if (field.key) {
          return getByPath(item, field.key);
        }
      }
      return getByPath(item, field);
    },
    resolveValue(item, column) {
      const key = column && column.key ? column.key : "";
      return getByPath(item, key);
    },
    resolveSearchValues(item) {
      return this.resolvedSearchFields.map((field) => this.resolveFieldValue(item, field));
    },
    resolveFilterValue(item, definition) {
      return this.resolveFieldValue(item, definition.value || definition.field || definition.key);
    },
    normalizeFilterItems(options) {
      return (Array.isArray(options) ? options : [])
        .map((option) => {
          if (option && typeof option === "object") {
            return {
              label: String(option.label ?? option.title ?? option.value ?? ""),
              value: String(option.value ?? ""),
            };
          }
          return {
            label: String(option || ""),
            value: String(option || ""),
          };
        })
        .filter((option) => option.label || option.value);
    },
    buildFilterItems(definition) {
      const providedItems = this.normalizeFilterItems(definition.options);
      if (providedItems.length) {
        return [{ label: definition.allLabel || "All", value: "" }, ...providedItems];
      }
      const values = uniqueSorted(this.normalizedRows.map((item) => this.resolveFilterValue(item, definition)));
      return [
        { label: definition.allLabel || "All", value: "" },
        ...values.map((value) => ({
          label: typeof definition.optionLabel === "function" ? definition.optionLabel(value) : value,
          value,
        })),
      ];
    },
    matchesFilterDefinition(item, definition) {
      const selected = normalizeSearchText(this.tableFilterValues[definition.key]);
      if (!selected) return true;
      return normalizeSearchText(this.resolveFilterValue(item, definition)) === selected;
    },
    syncTableFilterValues() {
      const nextValues = { ...(this.tableFilterValues || {}) };
      this.resolvedFilterDefinitions.forEach((definition) => {
        const selected = normalizeSearchText(nextValues[definition.key]);
        const matchesOption = definition.items.some((item) => normalizeSearchText(item.value) === selected);
        if (!selected || matchesOption) return;
        nextValues[definition.key] = "";
      });
      this.resolvedFilterDefinitions.forEach((definition) => {
        if (!(definition.key in nextValues)) {
          nextValues[definition.key] = "";
        }
      });
      this.tableFilterValues = nextValues;
    },
    syncExpandedRows() {
      if (!this.expandedRowKeys.length) return;
      this.expandedRowKeys = this.expandedRowKeys.filter((key) => this.tableItemKeys.has(String(key)));
    },
    sortJsonValue(value) {
      if (Array.isArray(value)) {
        return value.map((entry) => this.sortJsonValue(entry));
      }
      if (value && typeof value === "object") {
        return Object.keys(value)
          .sort((left, right) => left.localeCompare(right))
          .reduce((acc, key) => {
            acc[key] = this.sortJsonValue(value[key]);
            return acc;
          }, {});
      }
      return value;
    },
    formatJson(item) {
      try {
        return JSON.stringify(this.sortJsonValue(item), null, 2);
      } catch (err) {
        return JSON.stringify({ error: err && err.message ? err.message : "Unable to serialize row" }, null, 2);
      }
    },
    formatValue(item, column) {
      const value = this.resolveValue(item, column);
      if (column && typeof column.format === "function") {
        return column.format(value, item);
      }
      if (Array.isArray(value)) {
        return value.length ? value.join(", ") : "-";
      }
      if (value && typeof value === "object") {
        return JSON.stringify(value);
      }
      if (value === null || value === undefined || value === "") {
        return "-";
      }
      return value;
    },
  },
};
</script>

<style scoped>
.entity-table-wrap {
  border-radius: 12px;
}

.entity-data-table :deep(.v-table__wrapper) {
  overflow: auto;
}

.entity-data-table :deep(table) {
  min-width: 100%;
}

.entity-data-table :deep(thead th) {
  position: sticky;
  top: 0;
  z-index: 2;
  backdrop-filter: blur(12px);
  background: rgba(8, 14, 22, 0.94);
}

.entity-data-table :deep(tbody tr) {
  transition: background-color 0.16s ease, transform 0.16s ease;
}

.entity-data-table :deep(tbody td) {
  border-bottom: 1px solid rgba(99, 173, 219, 0.1);
  vertical-align: top;
}

.entity-data-table :deep(tbody tr:last-child td) {
  border-bottom: 0;
}

.entity-data-table :deep(tbody tr:hover > td) {
  transform: translateY(-1px);
  box-shadow: inset 0 0 0 1px rgba(108, 186, 228, 0.18);
  background: rgba(14, 23, 36, 0.88);
}

.entity-data-table :deep(.v-data-table__td--expanded-row) {
  width: 48px;
}

.entity-data-table__expand-header {
  display: inline-block;
  width: 18px;
}

.entity-data-table__expand-button {
  margin-inline-start: -4px;
}

.entity-data-table__expanded-row :deep(td) {
  padding: 0;
}

.entity-data-table__expanded-cell {
  background: rgba(6, 12, 22, 0.52);
}

.entity-json-panel {
  padding: 14px 16px;
  border-top: 1px solid rgba(99, 173, 219, 0.14);
  background: linear-gradient(180deg, rgba(11, 19, 31, 0.94), rgba(7, 13, 21, 0.88));
}

.entity-json-panel__label {
  margin-bottom: 10px;
  color: rgba(158, 196, 225, 0.8);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.entity-json {
  margin: 0;
  max-height: 360px;
  overflow: auto;
  color: rgba(229, 241, 252, 0.96);
  font-family: var(--font-mono);
  font-size: 0.79rem;
  line-height: 1.6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.entity-table-empty {
  padding: 18px 14px;
}

.entity-data-table :deep(.v-data-table__tr--mobile) {
  background: linear-gradient(180deg, rgba(10, 17, 28, 0.9), rgba(7, 12, 20, 0.84));
}

.entity-data-table :deep(.v-data-table__tr--mobile .v-data-table__td) {
  padding-block: 10px;
}

.entity-data-table :deep(.v-data-table__tr--mobile .v-data-table__td-title) {
  color: rgba(158, 196, 225, 0.78);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.entity-data-table :deep(.v-data-table__tr--mobile .v-data-table__td-value) {
  color: rgba(232, 242, 252, 0.96);
  overflow-wrap: anywhere;
}

.entity-data-table :deep(.target-actions),
.entity-data-table :deep(.banner-actions),
.entity-data-table :deep(.row-actions) {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
</style>
