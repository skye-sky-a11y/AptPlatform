<template>
  <div class="app-container">

    <div class="filter-container">
      <el-input
        v-model="listQuery.pid"
        placeholder="进程号"
        style="width: 400px;"
        class="filter-item"
        @keyup.enter.native="handleFilter"
      />
      <el-button
        v-waves
        class="filter-item"
        type="primary"
        icon="el-icon-search"
        @click="handleFilter"
      >
        Search
      </el-button>
      <!-- <el-button class="filter-item" style="margin-left: 10px;" type="primary" icon="el-icon-edit" @click="handleCreate">
        Add
      </el-button> -->
      <el-button
        v-waves
        :loading="downloadLoading"
        class="filter-item"
        type="primary"
        icon="el-icon-download"
        @click="handleDownload"
      >
        Export
      </el-button>
      <!-- <el-checkbox v-model="showReviewer" class="filter-item" style="margin-left:15px;" @change="tableKey=tableKey+1">
        reviewer
      </el-checkbox> -->
    </div>

    <el-table
      :key="tableKey"
      v-loading="listLoading"
      :data="list"
      border
      fit
      highlight-current-row
      style="width: 100%;"
      @sort-change="sortChange"
    >
      <el-table-column
        label="id#"
        sortable="custom"
        align="center"
        width="120"
        type="index"
      >
      </el-table-column>
      <el-table-column
        label="进程id"
        prop="pid"
        sortable="custom"
        align="center"
        width="120"
      >
        <template slot-scope="{row}">
          <span>{{ row.pid }}</span>
        </template>
      </el-table-column>
      <!-- <el-table-column label="Date" width="150px" align="center">
        <template slot-scope="{row}">
          <span>{{ row.timestamp | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
        </template>
      </el-table-column> -->
      <el-table-column
        label="调用程序的命令"
        width="120px"
      >
        <!-- <template slot-scope="{row}">
          <span class="link-type" @click="handleUpdate(row)">{{ row.grade }}</span>
          <!-- <el-tag>{{ row.type | typeFilter }}</el-tag> -->
        <template slot-scope="{row}">
          <span>{{ row.pname }}</span>
          <!-- <el-tag>{{ row.type | typeFilter }}</el-tag> -->
        </template>
      </el-table-column>
      <el-table-column
        label="调用文件绝对路径"
        width="124px"
        align="center"
      >
        <template slot-scope="{row}">
          <span>{{ row.absolute_file_path }}</span>
        </template>
      </el-table-column>

      <el-table-column
        label="当前目录"
        width="124px"
        align="center"
      >
        <template slot-scope="{row}">
          <span>{{ row.cwd }}</span>
        </template>
      </el-table-column>

      <el-table-column
        label="执行命令"
        width="124px"
        align="center"
      >
        <template slot-scope="{row}">
          <span>{{ row.cmdLine }}</span>
        </template>
      </el-table-column>

      <el-table-column
        label="主机名称"
        width="124px"
        align="center"
      >
        <template slot-scope="{row}">
          <span>{{ row.hostName }}</span>
        </template>
      </el-table-column>

      <el-table-column
        label="主机ip"
        width="124px"
        align="center"
      >
        <template slot-scope="{row}">
          <span>{{ row.hostip }}</span>
        </template>
      </el-table-column>

            <el-table-column
        label="userId"
        width="124px"
        align="center"
      >
        <template slot-scope="{row}">
          <span>{{ row.userId }}</span>
        </template>
      </el-table-column>

      <el-table-column
        label="groupIds"
        width="124px"
        align="center"
      >
        <template slot-scope="{row}">
          <span>{{ row.groupIds }}</span>
        </template>
      </el-table-column>

      <el-table-column
        label="时间戳"
        width="160px"
        align="center"
      >
        <template slot-scope="{row}">
          <span>{{ row.timestampNanos}}</span>
        </template>
      </el-table-column>

      <el-table-column
        label="Actions"
        align="center"
        width="230"
        class-name="small-padding fixed-width"
      >
        <template slot-scope="{row,$index}">
          <!-- <el-button
            type="primary"
            size="mini"
            @click="handleUpdate(row)"
          >
            Edit
          </el-button> -->
          <el-button
            v-if="row.status!='deleted'"
            size="mini"
            type="danger"
            @click="handleDelete(row,$index)"
          >
            Delete
          </el-button>
        </template>
      </el-table-column>
    </el-table>
        <template>
    <pagination
      :total="total"
      :page.sync="listQuery.page"
      :limit.sync="listQuery.limit"
      @pagination="getList"/>
    </template>

  </div>
</template>

<script>
import {
  fetchList,
  updateArticle,
  delete_once
} from "@/api/article"
import waves from "@/directive/waves" // waves directive

import Pagination from "@/components/Pagination" // secondary package based on el-pagination
import permission from '@/directive/permission/index.js' // 权限判断指令
const calendarTypeOptions = [
  { key: "CN", display_name: "China" },
  { key: "US", display_name: "USA" },
  { key: "JP", display_name: "Japan" },
  { key: "EU", display_name: "Eurozone" },
]

// arr to obj, such as { CN : "China", US : "USA" }
const calendarTypeKeyValue = calendarTypeOptions.reduce((acc, cur) => {
  acc[cur.key] = cur.display_name
  return acc
}, {})

export default {
  name: "ComplexTable",
  directives: { permission },
  components: { Pagination },
  directives: { waves },
  filters: {
    statusFilter(status) {
      const statusMap = {
        published: "success",
        draft: "info",
        deleted: "danger",
      }
      return statusMap[status]
    },
    typeFilter(type) {
      return calendarTypeKeyValue[type]
    },
  },
  data() {
    return {
      tableKey: 0,
      list: null,
      total: 0,
      listLoading: true,
      listQuery: {
        page: 1,
        pid: '',
        limit:20,
        sort: "",
      },
      importanceOptions: [1, 2, 3],
      calendarTypeOptions,
      statusOptions: ["deleted"],
      showReviewer: false,
      temp: {
        id: undefined,
        importance: 1,
        remark: "",
        timestamp: new Date(),
        title: "",
        type: "",
        status: "published",
      },
      dialogFormVisible: false,
      dialogStatus: "",
      textMap: {
        update: "Edit",
        create: "Create",
      },
      dialogPvVisible: false,
      pvData: [],
      rules: {
        type: [
          { required: true, message: "type is required", trigger: "change" },
        ],
        timestamp: [
          {
            type: "date",
            required: true,
            message: "timestamp is required",
            trigger: "change",
          },
        ],
        title: [
          { required: true, message: "title is required", trigger: "blur" },
        ],
      },
      downloadLoading: false,

    }
  },
  created() {
    this.getList()
  },
  methods: {
    getList() {
      this.listLoading = true
      fetchList(this.listQuery).then((response) => {
        this.list = response.infos
        this.total = response.total
        // Just to simulate the time of the request
        setTimeout(() => {
          this.listLoading = false
        }, 1.5 * 1000)
      })
    },
    handleFilter() {
      this.listQuery.page = 1
      this.getList()
    },
    handleModifyStatus(row, status) {
      this.$message({
        message: "操作Success",
        type: "success",
      })
      row.status = status
    },
    sortChange(data) {
      const { prop, order } = data
      if (prop === "id") {
        this.sortByID(order)
      }
      else if (prop === "pid"){
        this.sortByPID(order)
      }
    },
    sortByID(order) {
      if (order === "ascending") {
        this.listQuery.sort = "+id"
      } else {
        this.listQuery.sort = "-id"
      }
      this.handleFilter()
    },
    sortByPID(order) {
      if (order === "ascending") {
        this.listQuery.sort = "+pid"
      } else {
        this.listQuery.sort = "-pid"
      }
      this.handleFilter()
    },
    resetTemp() {
      this.temp = {
        id: undefined,
        importance: 1,
        remark: "",
        timestamp: new Date(),
        title: "",
        status: "published",
        type: "",
      }
    },


    handleUpdate(row) {
      this.temp = Object.assign({}, row) // copy obj
      this.temp.timestamp = new Date(this.temp.timestamp)
      this.dialogStatus = "update"
      this.dialogFormVisible = true
      this.$nextTick(() => {
        this.$refs["dataForm"].clearValidate()
      })
    },
    updateData() {
      this.$refs["dataForm"].validate((valid) => {
        if (valid) {
          const tempData = Object.assign({}, this.temp)
          tempData.timestamp = +new Date(tempData.timestamp) // change Thu Nov 30 2017 16:41:05 GMT+0800 (CST) to 1512031311464
          updateArticle(tempData).then(() => {
            const index = this.list.findIndex((v) => v.id === this.temp.id)
            this.list.splice(index, 1, this.temp)
            this.dialogFormVisible = false
            this.$notify({
              title: "Success",
              message: "Update Successfully",
              type: "success",
              duration: 2000,
            })
          })
        }
      })
    },
    handleDelete(row, index) {
      this.$notify({
        title: "Success",
        message: "Delete Successfully",
        type: "success",
        duration: 2000,
      })
      this.list.splice(index, 1)
      delete_once({"delete_id":row.id}).then((response) => {
        // this.list = response.data.infos
        // this.total = response.data.total
        // console.log(this.list)
        // Just to simulate the time of the request
        setTimeout(() => {
          this.listLoading = false
        }, 1.5 * 1000)
      })
      this.getList()
    },
    // handleFetchPv(pv) {
    //   fetchPv(pv).then(response => {
    //     this.pvData = response.data.pvData
    //     this.dialogPvVisible = true
    //   })
    // },
    handleDownload() {
      this.downloadLoading = true
      import("@/vendor/Export2Excel").then((excel) => {
        const tHeader = ["进程id", "调用程序的命令", "调用文件绝对路径", "当前目录", "主机名称","主机ip","时间戳","userId","groupIds"]
        const filterVal = [
          'id',
          'pname',
          'absolute_file_path',
          'cwd',
          'hostName',
          'hostip',
          'timestampNanos',
          'userId',
          'groupIds'
          ]
        const data = this.formatJson(filterVal)
        excel.export_json_to_excel({
          header: tHeader,
          data,
          filename: '日志报告',
        })
        this.downloadLoading = false
      })
    },
    formatJson(filterVal) {
      return this.list.map((v) =>
        filterVal.map(j => v[j])
      )
    },
  },
}
</script>
