import url from 'url'
import { aesECBEncrypt, getSignature, hmacSha1, randomString, rsaEncrypt } from './util'
import { logger } from './log'

export const signatureAccesstoken = (urlObj: URL, init: RequestInit, accessToken: string) => {
  const time = String(Date.now())
  const query = Object.fromEntries(urlObj.searchParams)
  const signature = getSignature({
    ...(init.method === 'GET' ? query : (init.body as any) || {}),
    Timestamp: time,
    AccessToken: accessToken
  })
  init.headers = {
    ...((init.headers as Record<string, string>) || {}),
    'Sign-Type': '1',
    Signature: signature,
    Timestamp: time,
    Accesstoken: accessToken
  }
}

export const signatureAppKey = (urlObj: URL, init: RequestInit, appkey: string) => {
  const time = String(Date.now())
  const query = Object.fromEntries(urlObj.searchParams)
  const signature = getSignature({
    ...(init.method === 'GET' ? query : (init.body as any) || {}),
    Timestamp: time,
    AppKey: appkey
  })
  init.headers = {
    ...((init.headers as Record<string, string>) || {}),
    'Sign-Type': '1',
    Signature: signature,
    Timestamp: time,
    AppKey: appkey
  }
}

export const signatureUpload = (
  urlObj: URL,
  init: RequestInit,
  rsaKey: {
    pubKey: string
    pkId: string
  },
  sessionKey: string
) => {
  const time = String(Date.now())
  const query = Object.fromEntries(urlObj.searchParams)
  const requestID = randomString('xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx')
  const uuid = randomString('xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx').slice(
    0,
    (16 + 16 * Math.random()) | 0
  )
  logger.debug(`upload query: ${JSON.stringify(query)}`)
  const params = aesECBEncrypt(query, uuid.substring(0, 16))
  const data = {
    SessionKey: sessionKey,
    Operate: init.method || 'GET',
    RequestURI: urlObj.pathname,
    Date: time,
    params
  }
  const encryptionText = rsaEncrypt(rsaKey.pubKey, uuid, 'base64')
  init.headers = {
    ...((init.headers as Record<string, string>) || {}),
    'X-Request-Date': time,
    'X-Request-ID': requestID,
    SessionKey: sessionKey,
    EncryptionText: encryptionText,
    PkId: rsaKey.pkId,
    Signature: hmacSha1(data, uuid)
  }
  urlObj.search = ''
  urlObj.hash = ''
  urlObj.searchParams.set('params', params)
}
