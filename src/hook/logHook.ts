import { logger } from '../log'

export const logHook = async (response: Response) => {
  const clonedResponse = response.clone()
  const url = clonedResponse.url
  const body = await clonedResponse.text()
  logger.debug(`url: ${url}, response: ${body}`)
}
