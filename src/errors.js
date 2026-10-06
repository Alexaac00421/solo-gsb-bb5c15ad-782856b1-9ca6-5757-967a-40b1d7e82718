'use strict';

/**
 * 统一的业务错误类型。所有“拒绝且不改变状态”的场景都抛出该错误，
 * 由 server.js 的错误处理中间件转换为 JSON 响应。
 */
class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

module.exports = { ApiError };
