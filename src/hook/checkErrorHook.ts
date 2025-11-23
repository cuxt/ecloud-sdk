import { checkError } from '../error'

export const checkErrorHook = async (response: Response) => {
  const clonedResponse = response.clone()
  const text = await clonedResponse.text()
  checkError(text)
}
