import fs from 'fs'
import path from 'path'
import {
  UserSignResponse,
  UserSizeInfoResponse,
  FamilyListResponse,
  FamilyUserSignResponse,
  ConfigurationOptions,
  ClientSession,
  PageQuery,
  MediaType,
  OrderByType,
  FileListResponse,
  RsaKeyResponse,
  RsaKey,
  UploadInitResponse,
  UploadCommitResponse,
  MultiUploadUrlsResponse,
  CreateFolderRequest,
  UploadCallbacks,
  PartNumberKey,
  RenameFolderRequest,
  CreateBatchTaskRequest,
  AccessTokenResponse,
  CreateFamilyBatchTaskRequest,
  CreateFamilyFolderRequest,
  RenameFamilyFolderRequest,
  CommitMultiFamilyUploadRequest,
  CommitMultiUploadRequest,
  FamilyRequest,
  initMultiUploadRequest,
  initMultiFamilyUploadRequest
} from './types'
import { logger } from './log'
import { asyncPool, calculateFileAndChunkMD5, hexToBase64, md5, partSize } from './util'
import { WEB_URL, API_URL, UserAgent, UPLOAD_URL } from './const'
import { signatureAccesstoken, signatureAppKey, signatureUpload } from './signature'
import { CloudAuthClient } from './CloudAuthClient'
import { logHook } from './hook'
import { MemoryStore, Store } from './store'
import { FileHandle } from 'fs/promises'

const config = {
  clientId: '538135150693412',
  model: 'KB2000',
  version: '9.0.6'
}

/**
 * 天翼网盘客户端
 * @public
 */
export class CloudClient {
  username: string
  password: string
  ssonCookie: string
  tokenStore: Store
  readonly authClient: CloudAuthClient
  readonly session: ClientSession
  private rsaKey: RsaKey
  private sessionKeyPromise: Promise<string>
  private accessTokenPromise: Promise<AccessTokenResponse>
  private generateRsaKeyPromise: Promise<RsaKeyResponse>

  constructor(_options: ConfigurationOptions) {
    this.#valid(_options)
    this.username = _options.username
    this.password = _options.password
    this.ssonCookie = _options.ssonCookie
    this.tokenStore = _options.token || new MemoryStore()
    this.authClient = new CloudAuthClient()
    this.session = { accessToken: '', sessionKey: '' }
    this.rsaKey = null
  }

  private async request(url: string | URL, options: RequestInit = {}): Promise<any> {
    const urlObj = typeof url === 'string' ? new URL(url) : url
    options.method = options.method || 'GET'
    options.headers = {
      'User-Agent': UserAgent,
      Referer: `${WEB_URL}/web/main/`,
      Accept: 'application/json;charset=UTF-8',
      ...options.headers
    }

    // Apply signatures
    if (urlObj.href.includes(API_URL)) {
      const accessToken = await this.getAccessToken()
      signatureAccesstoken(urlObj, options, accessToken)
    } else if (urlObj.href.includes(WEB_URL)) {
      if (urlObj.href.includes('/open')) {
        const appkey = '600100422'
        signatureAppKey(urlObj, options, appkey)
      }
      const sessionKey = await this.getSessionKey()
      urlObj.searchParams.set('sessionKey', sessionKey)
    } else if (urlObj.href.includes(UPLOAD_URL)) {
      const sessionKey = await this.getSessionKey()
      const rsaKey = await this.generateRsaKey()
      signatureUpload(urlObj, options, rsaKey, sessionKey)
    }

    const maxRetries = 2
    let lastError: Error

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const response = await fetch(urlObj.toString(), options)
        await logHook(response)

        if (response.status === 400) {
          const text = await response.text()
          try {
            const { errorCode, errorMsg } = JSON.parse(text) as {
              errorCode: string
              errorMsg: string
            }
            if (errorCode === 'InvalidAccessToken') {
              logger.debug(`InvalidAccessToken retry..., errorMsg: ${errorMsg}`)
              this.session.accessToken = ''
              continue
            } else if (errorCode === 'InvalidSessionKey') {
              logger.debug(`InvalidSessionKey retry..., errorMsg: ${errorMsg}`)
              this.session.sessionKey = ''
              continue
            }
          } catch (e) {
            logger.error(e)
          }
        }

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`)
        }

        return await response.json()
      } catch (error) {
        lastError = error as Error
        if (
          attempt < maxRetries &&
          (error.message.includes('408') ||
            error.message.includes('413') ||
            error.message.includes('429') ||
            error.message.includes('ETIMEDOUT') ||
            error.message.includes('ECONNRESET'))
        ) {
          continue
        }
        throw lastError
      }
    }
    throw lastError
  }

  #valid = (options: ConfigurationOptions) => {
    if (options.ssonCookie || options.token || (options.username && options.password)) return
    logger.error('valid')
    throw new Error('Please provide username and password or token or ssonCooike !')
  }

  async getSession() {
    const { accessToken, expiresIn, refreshToken } = await this.tokenStore.get()
    if (accessToken && expiresIn && expiresIn > Date.now()) {
      try {
        return await this.authClient.loginByAccessToken(accessToken)
      } catch (e) {
        // logger.error(e)
        throw e
      }
    }
    if (refreshToken) {
      try {
        const refreshTokenSession = await this.authClient.refreshToken(refreshToken)
        await this.tokenStore.update({
          accessToken: refreshTokenSession.accessToken,
          refreshToken: refreshTokenSession.refreshToken,
          expiresIn: new Date(Date.now() + refreshTokenSession.expiresIn * 1000).getTime()
        })
        return await this.authClient.loginByAccessToken(refreshTokenSession.accessToken)
      } catch (e) {
        // logger.error(e)
        throw e
      }
    }
    if (this.ssonCookie) {
      try {
        const loginToken = await this.authClient.loginBySsoCooike(this.ssonCookie)
        await this.tokenStore.update({
          accessToken: loginToken.accessToken,
          refreshToken: loginToken.refreshToken,
          expiresIn: new Date(Date.now() + 6 * 24 * 60 * 60 * 1000).getTime()
        })
        return loginToken
      } catch (e) {
        // logger.error(e)
        throw e
      }
    }
    if (this.username && this.password) {
      try {
        const loginToken = await this.authClient.loginByPassword(this.username, this.password)
        await this.tokenStore.update({
          accessToken: loginToken.accessToken,
          refreshToken: loginToken.refreshToken,
          expiresIn: new Date(Date.now() + 6 * 24 * 60 * 60 * 1000).getTime()
        })
        return loginToken
      } catch (e) {
        // logger.error(e)
        throw e
      }
    }
    throw new Error('Can not get session.')
  }

  /**
   * 获取 sessionKey
   * @returns sessionKey
   */
  async getSessionKey() {
    if (this.session.sessionKey) return this.session.sessionKey
    if (!this.sessionKeyPromise) {
      this.sessionKeyPromise = this.getSession()
        .then((result) => {
          this.session.sessionKey = result.sessionKey
          return result.sessionKey
        })
        .finally(() => {
          this.sessionKeyPromise = null
        })
    }
    return await this.sessionKeyPromise
  }

  /**
   * 获取 accessToken
   * @returns accessToken
   */
  async getAccessToken() {
    if (this.session.accessToken) return this.session.accessToken
    if (!this.accessTokenPromise) {
      this.accessTokenPromise = this.#getAccessTokenBySsKey()
        .then((result) => {
          this.session.accessToken = result.accessToken
          return result
        })
        .finally(() => {
          this.accessTokenPromise = null
        })
    }
    return (await this.accessTokenPromise).accessToken
  }

  /**
   * 获取 RSA key
   * @returns RSAKey
   */
  async generateRsaKey() {
    if (this.rsaKey && new Date(this.rsaKey.expire).getTime() > Date.now()) return this.rsaKey
    if (!this.generateRsaKeyPromise) {
      this.generateRsaKeyPromise = this.#generateRsaKey()
        .then((res) => {
          this.rsaKey = { expire: res.expire, pubKey: res.pubKey, pkId: res.pkId, ver: res.ver }
          return res
        })
        .finally(() => {
          this.generateRsaKeyPromise = null
        })
    }
    return await this.generateRsaKeyPromise
  }

  /**
   * 获取用户网盘存储容量信息
   * @returns 账号容量结果
   */
  getUserSizeInfo(): Promise<UserSizeInfoResponse> {
    return this.request(`${WEB_URL}/api/portal/getUserSizeInfo.action`)
  }

  /**
   * 个人签到任务
   * @returns 签到结果
   */
  userSign(): Promise<UserSignResponse> {
    return this.request(
      `${WEB_URL}/mkt/userSign.action?rand=${Date.now()}&clientType=TELEANDROID&version=${config.version}&model=${config.model}`
    )
  }

  /**
   * 获取 accessToken
   */
  #getAccessTokenBySsKey(): Promise<AccessTokenResponse> {
    return this.request(`${WEB_URL}/api/open/oauth2/getAccessTokenBySsKey.action`)
  }

  #generateRsaKey(): Promise<RsaKeyResponse> {
    return this.request(`${WEB_URL}/api/security/generateRsaKey.action`)
  }

  /**
   * 获取家庭信息
   * @returns 家庭列表信息
   */
  getFamilyList(): Promise<FamilyListResponse> {
    return this.request(`${API_URL}/open/family/manage/getFamilyList.action`)
  }

  /**
   * 家庭签到任务
   * @param familyId - 家庭id
   * @returns 签到结果
   * @deprecated 已无效
   */
  familyUserSign(familyId: string): Promise<FamilyUserSignResponse> {
    return this.request(
      `${API_URL}/open/family/manage/exeFamilyUserSign.action?familyId=${familyId}`
    )
  }

  /**
   * 获取文件列表
   * @param pageQuery - 查询参数
   * @returns
   */
  getListFiles(pageQuery?: PageQuery, familyId?: string): Promise<FileListResponse> {
    const defaultQuery = {
      pageNum: 1,
      pageSize: 60,
      mediaType: MediaType.ALL.toString(),
      orderBy: OrderByType.LAST_OP_TIME.toString(),
      descending: true,
      folderId: '',
      iconOption: 5
    }
    const query = {
      ...defaultQuery,
      ...pageQuery
    }
    const url = familyId
      ? `${API_URL}/open/family/file/listFiles.action`
      : `${API_URL}/open/file/listFiles.action`
    const fullUrl = new URL(url)
    Object.entries(query).forEach(
      ([key, value]) => value !== undefined && fullUrl.searchParams.set(key, value.toString())
    )
    if (familyId) fullUrl.searchParams.set('familyId', familyId)
    return this.request(fullUrl)
  }

  #isFamily(request: any): request is FamilyRequest {
    return 'familyId' in request && request.familyId !== undefined
  }

  createFolder(createFolderRequest: CreateFolderRequest | CreateFamilyFolderRequest) {
    const url = this.#isFamily(createFolderRequest)
      ? `${API_URL}/open/family/file/createFolder.action`
      : `${API_URL}/open/file/createFolder.action`
    const formData = new URLSearchParams()
    Object.entries(createFolderRequest).forEach(([k, v]) => formData.set(k, v.toString()))
    return this.request(url, {
      method: 'POST',
      body: formData,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })
  }

  renameFolder(renameFolderRequest: RenameFolderRequest | RenameFamilyFolderRequest) {
    let url = `${API_URL}/open/file/renameFolder.action`
    const formData = new URLSearchParams()
    formData.set('destFolderName', renameFolderRequest.folderName)
    formData.set('folderId', renameFolderRequest.folderId)
    if (this.#isFamily(renameFolderRequest)) {
      url = `${API_URL}/open/family/file/renameFolder.action`
      formData.set('familyId', renameFolderRequest.familyId)
    }
    return this.request(url, {
      method: 'POST',
      body: formData,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })
  }

  /**
   * 初始化上传
   * @param initMultiUploadRequest - 初始化请求
   * @returns
   */
  async initMultiUpload(
    initMultiUploadRequest: initMultiUploadRequest | initMultiFamilyUploadRequest
  ) {
    const { parentFolderId, fileName, fileSize, sliceSize, fileMd5, sliceMd5 } =
      initMultiUploadRequest
    let initParams = {
      parentFolderId,
      fileName,
      fileSize,
      sliceSize,
      ...(fileMd5 && sliceMd5 ? { fileMd5, sliceMd5 } : { lazyCheck: 1 })
    }
    let url = `${UPLOAD_URL}/person/initMultiUpload`
    if (this.#isFamily(initMultiUploadRequest)) {
      url = `${UPLOAD_URL}/family/initMultiUpload`
      initParams = Object.assign(initParams, {
        familyId: initMultiUploadRequest.familyId
      })
    }
    const fullUrl = new URL(url)
    Object.entries(initParams).forEach(([k, v]) => fullUrl.searchParams.set(k, v.toString()))
    return await this.request(fullUrl)
  }

  commitMultiUpload(
    commitMultiUploadRequest: CommitMultiUploadRequest | CommitMultiFamilyUploadRequest
  ) {
    const url = this.#isFamily(commitMultiUploadRequest)
      ? `${UPLOAD_URL}/family/commitMultiUploadFile`
      : `${UPLOAD_URL}/person/commitMultiUploadFile`
    const fullUrl = new URL(url)
    Object.entries(commitMultiUploadRequest).forEach(([k, v]) =>
      fullUrl.searchParams.set(k, v.toString())
    )
    return this.request(fullUrl)
  }

  checkTransSecond(params: {
    fileMd5: string
    sliceMd5: string
    uploadFileId: string
    familyId?: number
  }) {
    const url = this.#isFamily(params)
      ? `${UPLOAD_URL}/family/checkTransSecond`
      : `${UPLOAD_URL}/person/checkTransSecond`
    const fullUrl = new URL(url)
    Object.entries(params).forEach(
      ([k, v]) => v !== undefined && fullUrl.searchParams.set(k, v.toString())
    )
    return this.request(fullUrl)
  }

  async #partUpload(
    { partNumber, md5, buffer, uploadFileId, familyId },
    callbacks: UploadCallbacks = {}
  ) {
    const partInfo = `${partNumber}-${hexToBase64(md5)}`
    const multiUploadUrParams = { partInfo, uploadFileId }
    const url = familyId
      ? `${UPLOAD_URL}/family/getMultiUploadUrls`
      : `${UPLOAD_URL}/person/getMultiUploadUrls`
    const fullUrl = new URL(url)
    Object.entries(multiUploadUrParams).forEach(([k, v]) =>
      fullUrl.searchParams.set(k, v.toString())
    )
    const urls = await this.request(fullUrl)
    const { requestURL, requestHeader } = urls.uploadUrls[`partNumber_${partNumber}`]
    const headers = requestHeader.split('&').reduce((acc, pair) => {
      const [k, v] = pair.split('=')
      acc[k] = v
      return acc
    }, {})
    const response = await fetch(requestURL, { method: 'PUT', headers, body: buffer })
    if (!response.ok) throw new Error(`Upload failed: ${response.status}`)
  }

  async #singleUpload(
    { parentFolderId, filePath, fileName, fileSize, fileMd5, sliceSize, familyId },
    callbacks: UploadCallbacks = {}
  ) {
    const sliceMd5 = fileMd5
    let fd: FileHandle | null
    try {
      const res = await this.initMultiUpload({
        parentFolderId,
        fileName,
        fileSize,
        sliceSize,
        fileMd5,
        sliceMd5,
        familyId
      })
      const { uploadFileId, fileDataExists } = res.data
      if (!fileDataExists) {
        fd = await fs.promises.open(filePath, 'r')
        const buffer = Buffer.alloc(fileSize)
        await fd.read(buffer, 0, fileSize)
        await this.#partUpload(
          { partNumber: 1, md5: fileMd5, buffer, uploadFileId, familyId },
          callbacks
        )
      } else {
        callbacks.onProgress?.(100)
      }
      const commitResult = {
        ...(await this.commitMultiUpload({ fileMd5, sliceMd5, uploadFileId, familyId })),
        fileDataExists
      }
      callbacks.onComplete?.(commitResult)
      return commitResult
    } catch (e) {
      callbacks.onError?.(e)
      throw e
    } finally {
      fd?.close()
    }
  }

  /**
   * 大文件分块上传
   */
  async #multiUpload(
    { parentFolderId, filePath, fileName, fileSize, fileMd5, sliceSize, chunkMd5s, familyId },
    callbacks: UploadCallbacks = {}
  ) {
    const sliceMd5 = md5(chunkMd5s.join('\n'))
    let fd: FileHandle | null
    try {
      const res = await this.initMultiUpload({
        parentFolderId,
        fileName,
        fileSize,
        sliceSize,
        familyId
      })
      const { uploadFileId } = res.data
      const checkRes = await this.checkTransSecond({ fileMd5, sliceMd5, uploadFileId, familyId })
      const { fileDataExists } = checkRes.data
      if (!fileDataExists) {
        fd = await fs.promises.open(filePath, 'r')
        const progressMap: { [key: PartNumberKey]: number } = {}
        await asyncPool(
          5,
          chunkMd5s.map((_, i) => i),
          async (i) => {
            const partNumber = i + 1
            const position = i * sliceSize
            const length = Math.min(sliceSize, fileSize - position)
            const buffer = Buffer.alloc(length)
            await fd.read(buffer, 0, length, position)
            await this.#partUpload(
              { partNumber, md5: chunkMd5s[i], buffer, uploadFileId, familyId },
              {
                onProgress: (chunkProgress) => {
                  progressMap[`partNumber_${partNumber}`] = chunkProgress
                  const totalProgress =
                    Object.values(progressMap).reduce((sum, p) => sum + p, 0) / chunkMd5s.length
                  callbacks.onProgress?.(totalProgress)
                },
                onError: callbacks.onError
              }
            )
          }
        )
      } else callbacks.onProgress?.(100)
      const commitResult = {
        ...(await this.commitMultiUpload({
          fileMd5,
          sliceMd5,
          uploadFileId,
          lazyCheck: 1,
          familyId
        })),
        fileDataExists
      }
      callbacks.onComplete?.(commitResult)
      return commitResult
    } catch (e) {
      callbacks.onError?.(e)
      throw e
    } finally {
      fd?.close()
    }
  }

  /**
   * 文件上传
   * @param param - 上传参数
   * @param callbacks - 上传回调
   * @returns
   */
  async upload(
    param: { parentFolderId: string; filePath: string; familyId?: string },
    callbacks: UploadCallbacks = {}
  ) {
    const { filePath, parentFolderId, familyId } = param
    const { size } = await fs.promises.stat(filePath)
    const fileName = encodeURIComponent(path.basename(filePath))
    const sliceSize = partSize(size)
    const { fileMd5, chunkMd5s } = await calculateFileAndChunkMD5(filePath, sliceSize)
    return chunkMd5s.length === 1
      ? this.#singleUpload(
          { parentFolderId, filePath, fileName, fileSize: size, fileMd5, sliceSize, familyId },
          callbacks
        )
      : this.#multiUpload(
          {
            parentFolderId,
            filePath,
            fileName,
            fileSize: size,
            fileMd5,
            sliceSize,
            chunkMd5s,
            familyId
          },
          callbacks
        )
  }

  /**
   * 检测任务状态
   * @param type - 任务类型
   * @param taskId - 任务Id
   * @param maxAttempts - 重试次数
   * @param interval - 重试间隔
   * @returns
   */
  async checkTaskStatus(
    type: string,
    taskId: string,
    maxAttempts = 120,
    interval = 500
  ): Promise<{
    successedFileIdList?: number[]
    taskId: string
    taskStatus: number
  }> {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const formData = new URLSearchParams()
        formData.set('type', type)
        formData.set('taskId', taskId)
        const result = await this.request(`${API_URL}/open/batch/checkBatchTask.action`, {
          method: 'POST',
          body: formData,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        })
        const { taskStatus, successedFileIdList } = result as {
          taskStatus: number
          successedFileIdList: number[]
        }
        if (taskStatus === -1) {
          logger.error('创建任务异常')
          return {
            taskId,
            taskStatus
          }
        }
        //重名
        if (taskStatus === 2) {
          logger.error('文件重名任务异常')
          return {
            taskId,
            taskStatus
          }
        }
        //成功
        if (taskStatus === 4) {
          return { successedFileIdList, taskId, taskStatus }
        }
      } catch (e) {
        logger.error(`Check task status attempt ${attempt + 1} failed:` + e)
      }
      await new Promise((resolve) => setTimeout(resolve, interval))
    }
  }

  /**
   * 创建任务
   * @param createBatchTaskRequest - 创建任务参数
   * @returns
   */
  async createBatchTask(
    createBatchTaskRequest: CreateBatchTaskRequest | CreateFamilyBatchTaskRequest
  ) {
    const formData = new URLSearchParams()
    formData.set('type', createBatchTaskRequest.type)
    formData.set('taskInfos', JSON.stringify(createBatchTaskRequest.taskInfos))
    if (createBatchTaskRequest.targetFolderId) {
      formData.set('targetFolderId', createBatchTaskRequest.targetFolderId)
    }
    if (this.#isFamily(createBatchTaskRequest)) {
      formData.set('familyId', createBatchTaskRequest.familyId)
    }
    try {
      const result = await this.request(`${API_URL}/open/batch/createBatchTask.action`, {
        method: 'POST',
        body: formData,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      })
      const { taskId } = result as { taskId: string }
      return await this.checkTaskStatus(createBatchTaskRequest.type, taskId)
    } catch (error) {
      logger.error('Batch task creation failed:' + error)
      throw error
    }
  }

  /**
   * 获取文件下载路径
   * @param params - 文件参数
   * @returns
   */
  getFileDownloadUrl(params: { fileId: string; familyId?: string }) {
    const url = params.familyId
      ? `${API_URL}/open/family/file/getFileDownloadUrl.action`
      : `${API_URL}/open/file/getFileDownloadUrl.action`
    const fullUrl = new URL(url)
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        fullUrl.searchParams.set(key, value.toString())
      }
    })
    return this.request(fullUrl)
  }
}
