import Vue from 'vue'
import Router from 'vue-router'

Vue.use(Router)

/* Layout */
import Layout from '@/layout'

/**
 * Note: sub-menu only appear when route children.length >= 1
 * Detail see: https://panjiachen.github.io/vue-element-admin-site/guide/essentials/router-and-nav.html
 *
 * hidden: true                   if set true, item will not show in the sidebar(default is false)
 * alwaysShow: true               if set true, will always show the root menu
 *                                if not set alwaysShow, when item has more than one children route,
 *                                it will becomes nested mode, otherwise not show the root menu
 * redirect: noRedirect           if set noRedirect will no redirect in the breadcrumb
 * name:'router-name'             the name is used by <keep-alive> (must set!!!)
 * meta : {
    roles: ['admin','editor']    control the page roles (you can set multiple roles)
    title: 'title'               the name show in sidebar and breadcrumb (recommend set)
    icon: 'svg-name'/'el-icon-x' the icon show in the sidebar
    breadcrumb: false            if set false, the item will hidden in breadcrumb(default is true)
    activeMenu: '/example/list'  if set path, the sidebar will highlight the path you set
  }
 */

/**
 * constantRoutes
 * a base page that does not have permission requirements
 * all roles can be accessed
 */
export const constantRoutes = [
  {
    path: '/login',
    component: () => import('@/views/login/index'),
    hidden: true
  },

  {
    path: '/404',
    component: () => import('@/views/404'),
    hidden: true
  },

  {
    path: '/',
    component: Layout,
    redirect: '/dashboard',
    children: [{
      path: 'dashboard',
      name: 'Dashboard',
      component: () => import('@/views/dashboard/index'),
      meta: { title: '总览', icon: 'dashboard' }
    }]
  },
  {
    path: '/shujucaiji',
    component: Layout,
    redirect: '/shujucaiji/shujuzhanshi',
    name: 'Shujucaiji',
    meta: { title: '数据采集', icon: 'list' },
    alwaysShow: true,
    children: [
      {
        path: 'shujuzhanshi',
        name: 'shujuzhanshi',
        component: () => import('@/views/shujucaiji/index'),
        meta: { title: '数据展示', icon: 'form' }
      },
      {
        path: 'jiandanruqinjiance',
        name: 'jiandanruqinjiance',
        component: () => import('@/views/jiandanruqinjiance/index'),
        meta: { title: '简单入侵检测', icon: 'lock' }
      }
    ]
  },
  {
    path: '/shijianguanli',
    component: Layout,
    redirect: '/shijianguanli/shujuyasuo',
    name: 'Shijianguanli',
    meta: { title: '事件管理', icon: 'list' },
    alwaysShow: true,
    children: [
      {
        path: 'shujuyasuo',
        name: 'shujuyasuo',
        component: () => import('@/views/shujuyasuo/index'),
        meta: { title: '数据压缩情况', icon: 'chart' }
      }
    ]
  },

  {
    path: '/weixiekongzhi',
    component: Layout,
    redirect: '/weixiekongzhi/yichangjiance',
    name: 'Weixiekongzhi',
    meta: { title: '威胁控制', icon: 'list' },
    alwaysShow: true,
    children: [
      {
        path: 'yichangjiance',
        name: 'yichangjiance',
        component: () => import('@/views/yichangjiance/index'),
        meta: { title: '异常检测', icon: 'lock' }
      }
      // {
      //   path: 'gongjilian',
      //   name: 'gongjilian',
      //   component: () => import('@/views/gongjilian/index'),
      //   meta: { title: '攻击链', icon: 'lock' }
      // }
      // {
      //   path: 'heimingdan',
      //   name: 'heimingdan',
      //   component: () => import('@/views/heimingdan/index'),
      //   meta: { title: '黑名单管理', icon: 'table' }
      // },
      // {
      //   path: 'baimingdan',
      //   name: 'baimingdan',
      //   component: () => import('@/views/baimingdan/index'),
      //   meta: { title: '白名单管理', icon: 'table' }
      // },
      // {
      //   path: 'lujingtu',
      //   name: 'lujingtu',
      //   component: () => import('@/views/lujingtu/index'),
      //   meta: { title: '路径图', icon: 'chart' }
      // }
    ]
  },
  {
    path: 'external-link',
    component: Layout,
    children: [
      {
        path: 'http://10.12.42.160/apt/apt-test.pdf',
        meta: { title: '攻击图', icon: 'link' }
      }
    ]
  },
  { path: '*', redirect: '/404', hidden: true }
]

const createRouter = () => new Router({
  // mode: 'history', // require service support
  scrollBehavior: () => ({ y: 0 }),
  routes: constantRoutes
})

const router = createRouter()

// Detail see: https://github.com/vuejs/vue-router/issues/1234#issuecomment-357941465
export function resetRouter() {
  const newRouter = createRouter()
  router.matcher = newRouter.matcher // reset router
}

export default router
