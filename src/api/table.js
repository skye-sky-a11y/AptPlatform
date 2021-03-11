import request from '@/utils/request'

export function getList(params) {
  return request({
    url: 'https://47.97.160.248/',
    method: 'get',
    params
  })
}
