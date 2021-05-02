import request from '@/utils/request'
let base = 'http://127.0.0.1:5000/api'
export function login(data) {
  return request({
    url: `${base}/login`,
    // url: '/vue-admin-template/user/login',
    method: 'post',
    auth: data
  })
}

// export function getInfo(token) {
//   return request({
//     url: '/vue-admin-template/user/info',
//     method: 'get',
//     params: { token }
//   })
// }
<<<<<<< HEAD
export function attack_info(data) {
  return request({
    url: `${base}/attack_log`,
    // url: '/vue-admin-template/user/login',
    method: 'get',
    params: {data}
  })
}
=======
>>>>>>> 63dfc8db1d33b65b45b0c7e027f643ea00a18e36
export function getInfo(token) {
  return request({
    url: `${base}/userinfo`,
    // url: '/vue-admin-template/user/info',
    method: 'get',
    params: { token }
  })
}
export function logout() {
  return request({
    url: '/vue-admin-template/user/logout',
    method: 'post'
  })
}
