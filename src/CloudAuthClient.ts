import { logger } from './log'
import {
  WEB_URL,
  API_URL,
  AUTH_URL,
  UserAgent,
  clientSuffix,
  AppID,
  ClientType,
  ReturnURL,
  AccountType
} from './const'
import { RefreshTokenSession, CacheQuery, TokenSession } from './types'
import { rsaEncrypt } from './util'
import { logHook, checkErrorHook } from './hook'

interface LoginResponse {
  result: number
  msg: string
  toUrl: string
}

/**
 * @public
 */
export class CloudAuthClient {
  private readonly defaultHeaders = {
    'User-Agent': UserAgent,
    Accept: 'application/json;charset=UTF-8'
  }

  constructor() {}

  private async http(
    url: string | URL,
    options: RequestInit = {},
    returnText = false
  ): Promise<any> {
    const finalOptions: RequestInit = {
      ...options,
      headers: {
        ...this.defaultHeaders,
        ...options.headers
      }
    }

    const res = await fetch(url.toString(), finalOptions)

    // Clone 避免 hook 消耗 body
    const clone = res.clone()
    await logHook(clone)
    await checkErrorHook(clone)

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`)
    }

    return returnText ? await res.text() : await res.json()
  }

  private async request(url: string | URL, options: RequestInit = {}): Promise<any> {
    return this.http(url, options, false)
  }

  private async requestText(url: string | URL, options: RequestInit = {}): Promise<string> {
    return this.http(url, options, true)
  }

  /** 获取公钥及加密前缀 */
  getEncrypt(): Promise<{ data: { pubKey: string; pre: string } }> {
    return this.request(`${AUTH_URL}/api/logbox/config/encryptConf.do`, { method: 'POST' })
  }

  async getLoginForm(): Promise<CacheQuery> {
    const url = new URL(`${WEB_URL}/api/portal/unifyLoginForPC.action`)
    url.searchParams.set('appId', AppID)
    url.searchParams.set('clientType', ClientType)
    url.searchParams.set('returnURL', ReturnURL)
    url.searchParams.set('timeStamp', Date.now().toString())

    const html = await this.requestText(url)

    const find = (regex: RegExp) => {
      const m = html.match(regex)
      if (!m) throw new Error(`Missing field: ${regex}`)
      return m[1]
    }

    return {
      captchaToken: find(/'captchaToken' value='(.+?)'/),
      lt: find(/lt = "(.+?)"/),
      paramId: find(/paramId = "(.+?)"/),
      reqId: find(/reqId = "(.+?)"/)
    }
  }

  /** 构建登录表单 */
  #buildLoginForm(
    encrypt: { pubKey: string; pre: string },
    appConf: CacheQuery,
    username: string,
    password: string
  ): URLSearchParams {
    const form = new URLSearchParams()

    const usernameEnc = rsaEncrypt(encrypt.pubKey, username)
    const passwordEnc = rsaEncrypt(encrypt.pubKey, password)

    const data = {
      appKey: AppID,
      accountType: AccountType,
      validateCode: '',
      captchaToken: appConf.captchaToken,
      dynamicCheck: 'FALSE',
      clientType: '1',
      cb_SaveName: '3',
      isOauth2: 'false',
      returnUrl: ReturnURL,
      paramId: appConf.paramId,
      userName: `${encrypt.pre}${usernameEnc}`,
      password: `${encrypt.pre}${passwordEnc}`
    }

    Object.entries(data).forEach(([k, v]) => form.set(k, v))
    return form
  }

  /** 获取 PC 登录 session */
  async getSessionForPC(param: {
    redirectURL?: string
    accessToken?: string
  }): Promise<TokenSession> {
    const fullUrl = new URL(`${API_URL}/getSessionForPC.action`)
    const params = {
      appId: AppID,
      ...clientSuffix(),
      ...param
    }
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) fullUrl.searchParams.set(key, value.toString())
    })

    return await this.request(fullUrl, { method: 'POST' })
  }

  /** 用户名密码登录 */
  async loginByPassword(username: string, password: string): Promise<TokenSession> {
    logger.debug('loginByPassword...')
    try {
      const [encryptRes, appConf] = await Promise.all([this.getEncrypt(), this.getLoginForm()])
      const encrypt = encryptRes.data
      const formData = this.#buildLoginForm(encrypt, appConf, username, password)

      const loginRes: LoginResponse = await this.request(
        `${AUTH_URL}/api/logbox/oauth2/loginSubmit.do`,
        {
          method: 'POST',
          headers: {
            Referer: AUTH_URL,
            lt: appConf.lt,
            REQID: appConf.reqId,
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: formData
        }
      )

      return await this.getSessionForPC({ redirectURL: loginRes.toUrl })
    } catch (e) {
      logger.error(e)
      throw e
    }
  }

  /** accessToken 登录 */
  async loginByAccessToken(accessToken: string): Promise<TokenSession> {
    logger.debug('loginByAccessToken...')
    return this.getSessionForPC({ accessToken })
  }

  /** SSO cookie 登录 */
  async loginBySsoCooike(cookie: string): Promise<TokenSession> {
    logger.debug('loginBySsoCooike...')

    const u = new URL(`${WEB_URL}/api/portal/unifyLoginForPC.action`)
    u.searchParams.set('appId', AppID)
    u.searchParams.set('clientType', ClientType)
    u.searchParams.set('returnURL', ReturnURL)
    u.searchParams.set('timeStamp', Date.now().toString())

    // 第一次请求登录页面
    const first = await fetch(u, { headers: this.defaultHeaders })

    // 第二次携带 SSO cookie
    const second = await fetch(first.url, {
      headers: {
        ...this.defaultHeaders,
        Cookie: `SSON=${cookie}`
      }
    })

    return this.getSessionForPC({ redirectURL: second.url })
  }

  /** 刷新 token */
  refreshToken(refreshToken: string): Promise<RefreshTokenSession> {
    const formData = new URLSearchParams()
    formData.set('clientId', AppID)
    formData.set('refreshToken', refreshToken)
    formData.set('grantType', 'refresh_token')
    formData.set('format', 'json')

    return this.request(`${AUTH_URL}/api/oauth2/refreshToken.do`, {
      method: 'POST',
      body: formData,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })
  }
}
