<template>
  <DataPanel
    :title="title"
    :subtitle="subtitle"
    :loading="loading"
    :show-skeleton="false"
    :error="error"
    :last-updated="lastUpdated"
    :variant="variant"
    :collapsible="collapsible"
    :default-collapsed="defaultCollapsed"
    :count="normalizedRows.length"
    :count-label="countLabel"
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

    <div v-if="valueFilters.length" class="d-flex flex-wrap align-center ga-2 mb-3">
      <span class="text-caption text-medium-emphasis">Filters:</span>
      <v-chip
        v-for="(vf, index) in valueFilters"
        :key="`vf-${index}-${vf.key}-${vf.value}`"
        size="small"
        variant="tonal"
        :color="vf.mode === 'exclude' ? 'error' : 'success'"
        :prepend-icon="vf.mode === 'exclude' ? 'mdi-minus-circle-outline' : 'mdi-plus-circle-outline'"
        closable
        class="value-filter-chip"
        @click="toggleValueFilterMode(index)"
        @click:close="removeValueFilter(index)"
      >
        {{ vf.label || vf.key }}: {{ vf.value }}
        <v-tooltip activator="parent" location="bottom">
          Click to switch to {{ vf.mode === "exclude" ? "include" : "exclude" }}
        </v-tooltip>
      </v-chip>
      <v-btn size="small" variant="text" color="secondary" @click="clearValueFilters">Clear all</v-btn>
    </div>
    <div class="d-flex justify-end mb-2">
      <v-menu :close-on-content-click="false" location="bottom end">
        <template #activator="{ props: menuProps }">
          <v-btn
            v-bind="menuProps"
            icon="mdi-view-column-outline"
            size="small"
            variant="outlined"
            color="secondary"
            aria-label="Columns"
          >
            <v-icon icon="mdi-view-column-outline" />
            <v-tooltip activator="parent" location="bottom">Columns</v-tooltip>
          </v-btn>
        </template>
        <v-card class="pa-3 column-picker-menu" min-width="220" rounded="lg">
          <div class="text-caption text-medium-emphasis mb-2">Show columns</div>
          <v-checkbox
            v-for="column in pickableColumns"
            :key="`colpick-${column.key}`"
            v-model="visibleColumnKeys"
            :value="column.key"
            :label="column.label || column.key"
            density="compact"
            hide-details
            class="column-picker-menu__item"
          />
        </v-card>
      </v-menu>
    </div>
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
          <div
            class="cell-filter-wrap"
            :class="{ 'cell-filter-wrap--filterable': isFilterableColumn(column, slotProps.item) }"
          >
            <span class="cell-filter-wrap__content">
              <slot
                :name="`cell-${column.key}`"
                :item="slotProps.item"
                :value="resolveValue(slotProps.item, column)"
              >
                {{ formatValue(slotProps.item, column) }}
              </slot>
            </span>
            <span v-if="isFilterableColumn(column, slotProps.item)" class="cell-filter-wrap__actions">
              <button
                type="button"
                class="cell-filter-btn cell-filter-btn--include"
                aria-label="Filter for value"
                @click.stop="addValueFilter(column, slotProps.item, 'include')"
              >
                <v-icon icon="mdi-plus" size="12" />
              </button>
              <button
                type="button"
                class="cell-filter-btn cell-filter-btn--exclude"
                aria-label="Filter out value"
                @click.stop="addValueFilter(column, slotProps.item, 'exclude')"
              >
                <v-icon icon="mdi-minus" size="12" />
              </button>
            </span>
          </div>
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
    collapsible: {
      type: Boolean,
      default: true,
    },
    defaultCollapsed: {
      type: Boolean,
      default: false,
    },
    countLabel: {
      type: String,
      default: "rows",
    },
  },
  data() {
    return {
      currentPage: 1,
      expandedRowKeys: [],
      tableSearchQuery: "",
      tableFilterValues: {},
      visibleColumnKeys: [],
      valueFilters: [],
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
      // Kibana/Grafana-style include/exclude pills. Multiple "include" pins
      // on the *same* field are OR'd together (e.g. "proto: tcp OR udp"),
      // different fields are AND'd, and "exclude" pins always AND (each one
      // narrows further) - matches how Kibana's pinned filters behave.
      const includeGroups = new Map();
      const excludeFilters = [];
      this.valueFilters.forEach((vf) => {
        if (vf.mode === "exclude") {
          excludeFilters.push(vf);
        } else {
          if (!includeGroups.has(vf.key)) includeGroups.set(vf.key, []);
          includeGroups.get(vf.key).push(vf);
        }
      });
      return this.normalizedRows.filter((item) => {
        if (query && !matchesSearch(query, this.resolveSearchValues(item))) {
          return false;
        }
        if (!activeFilters.every((definition) => this.matchesFilterDefinition(item, definition))) {
          return false;
        }
        for (const [key, filters] of includeGroups) {
          const cellValue = normalizeSearchText(getByPath(item, key));
          if (!filters.some((f) => normalizeSearchText(f.value) === cellValue)) return false;
        }
        for (const vf of excludeFilters) {
          if (normalizeSearchText(getByPath(item, vf.key)) === normalizeSearchText(vf.value)) return false;
        }
        return true;
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
    pickableColumns() {
      return this.normalizedColumns.filter((column) => column.key !== "actions");
    },
    visibleColumns() {
      const visible = new Set(this.visibleColumnKeys);
      return this.normalizedColumns.filter((column) => column.key === "actions" || visible.has(column.key));
    },
    tableHeaders() {
      const headers = this.visibleColumns.map((column) => ({
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
    valueFilters: {
      deep: true,
      handler() {
        this.currentPage = 1;
        this.syncExpandedRows();
      },
    },
    normalizedColumns: {
      handler() {
        this.syncVisibleColumnKeys();
      },
    },
  },
  created() {
    this.syncTableFilterValues();
    this.syncVisibleColumnKeys();
  },
  methods: {
    syncVisibleColumnKeys() {
      const validKeys = new Set(this.normalizedColumns.map((column) => column.key));
      const kept = this.visibleColumnKeys.filter((key) => validKeys.has(key));
      const missing = [...validKeys].filter((key) => !this.visibleColumnKeys.includes(key) && !kept.includes(key));
      if (kept.length === this.visibleColumnKeys.length && !missing.length) return;
      this.visibleColumnKeys = [...kept, ...missing];
    },
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
    isFilterableColumn(column, item) {
      if (!column || !column.key) return false;
      if (column.key === "actions" || column.key === "data-table-expand") return false;
      if (column.noFilter) return false;
      const value = this.resolveValue(item, column);
      if (value === null || value === undefined || value === "") return false;
      if (Array.isArray(value) || typeof value === "object") return false;
      return true;
    },
    addValueFilter(column, item, mode) {
      const key = column.key;
      const value = String(this.resolveValue(item, column));
      const label = column.label || key;
      const existingIndex = this.valueFilters.findIndex((f) => f.key === key && f.value === value);
      if (existingIndex >= 0) {
        if (this.valueFilters[existingIndex].mode === mode) {
          this.valueFilters.splice(existingIndex, 1); // same pill clicked again - toggle off
        } else {
          this.valueFilters[existingIndex].mode = mode;
        }
        return;
      }
      this.valueFilters.push({ key, value, mode, label });
    },
    toggleValueFilterMode(index) {
      const filter = this.valueFilters[index];
      if (!filter) return;
      filter.mode = filter.mode === "exclude" ? "include" : "exclude";
    },
    removeValueFilter(index) {
      this.valueFilters.splice(index, 1);
    },
    clearValueFilters() {
      this.valueFilters = [];
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

.cell-filter-wrap {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 6px;
  min-width: 0;
}

.cell-filter-wrap__content {
  min-width: 0;
  flex: 1 1 auto;
}

.cell-filter-wrap__actions {
  display: inline-flex;
  gap: 2px;
  flex: 0 0 auto;
  opacity: 0;
  transition: opacity 0.12s ease;
}

.cell-filter-wrap--filterable:hover .cell-filter-wrap__actions,
.cell-filter-wrap__actions:focus-within {
  opacity: 1;
}

.cell-filter-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  padding: 0;
  border: none;
  border-radius: 3px;
  cursor: pointer;
  color: rgba(229, 241, 252, 0.92);
}

.cell-filter-btn--include {
  background: rgba(53, 230, 177, 0.24);
}

.cell-filter-btn--include:hover {
  background: rgba(53, 230, 177, 0.46);
}

.cell-filter-btn--exclude {
  background: rgba(255, 99, 99, 0.24);
}

.cell-filter-btn--exclude:hover {
  background: rgba(255, 99, 99, 0.46);
}

.value-filter-chip {
  cursor: pointer;
}

.column-picker-menu {
  max-height: 320px;
  overflow-y: auto;
  border: 1px solid rgba(104, 178, 221, 0.2);
  background: linear-gradient(180deg, rgba(7, 14, 24, 0.98), rgba(4, 10, 18, 0.98));
  box-shadow: 0 18px 38px rgba(2, 8, 14, 0.34);
}

.column-picker-menu__item {
  margin: 0;
}

.column-picker-menu__item :deep(.v-selection-control) {
  min-height: 0;
}
</style>
