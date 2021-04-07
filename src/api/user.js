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
