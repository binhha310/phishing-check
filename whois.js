import isIp from 'is-ip'
import whoiser from 'whoiser'
import { replace, compose, trim } from 'ramda'

const whoisServer = 'whois.markmonitor.com'

const getInfo = async function(url) {
  const whois = isIp(url) ? whoiser.ip : whoiser.domain
  const { [whoisServer]: info } = await whois(url, { host: whoisServer })
  return info
}

export default getInfo
