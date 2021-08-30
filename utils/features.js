import isIp from 'is-ip'
import normalizeUrl from 'normalize-url';
import UrlPattern from 'url-pattern'
import https from 'https'
import getInfo from '../whois.js'
import WhoisLight from 'whois-light'
import getWebsiteFavicon from 'get-website-favicon'
import nodePortScanner from 'node-port-scanner'
import { XMLHttpRequest } from 'xmlhttprequest'
import jsdom from 'jsdom'
import caa from 'caa'
import fetch from 'node-fetch'
//import { AlexaRank } from 'alexa-rank-nodejs'
import * as fsPromise from 'fs/promises'

const pattern = new UrlPattern('(:protocol\\://)(:subdomain.):domain.:tld(/*)')
const static_domain = await fsPromise.readFile('./phishing-domains.txt', 'utf-8').then(data => data.split('\n'))

function yearDiff(dt1, dt2) {
    var diffYear =(dt2.getTime() - dt1.getTime()) / 1000;
    diffYear /= (60 * 60 * 24);
    return Math.abs(Math.round(diffYear/365.25));
}

var getSourceAsDOM = function(url) {
    return new Promise((resolve, reject) => {
        const request = new XMLHttpRequest()
        request.open("GET", url, false)
        request.onreadystatechange = function() {
            if (this.readyState == 4 && this.status >= 200) {
                const dom = new jsdom.JSDOM(request.responseText).window.document
                resolve(dom)
            }
        }
        request.send()
    })
}

const sameDomain = url => src => {
    try {
     const s = pattern.match(src).domain
    const u = pattern.match(url).domain
    return s === u
    } catch (error) {
        console.log(src)
    }
}

const statistical_report = function(url) {
	const p = pattern.match(url)
	const domain = `${p.domain}.${p.tld}`
    return static_domain.find(e => e === domain) !== undefined ? -1 : 1
}

const links_pointing_to_page = function(url) {
    return 0
}

const google_index = function(url) {
    return 1
}

const page_rank = function(url) {
    return 1
}

const web_traffic = function(url) {
    // const getRank = record => record.data.site_rank

    // const data = await AlexaRank.siteinfo(url)
    // const rank = getRank(data)
    // if (rank < 100000) return 1
    // else if (rank >= 100000 && rank < 150000) return 0
    // else return -1
    return 0
}

const dnsrecord = async function(url) {
    const records = await caa(url)
    if (records.length > 0) return 1
    else return -1
}

const age_of_domain = function(info) {
    const creation_date = info['Creation Date']
    const expiration_date = info['Registry Expiry Date']

    const yeardiff = creation_date && expiration_date ? yearDiff(new Date(creation_date), new Date(expiration_date)) : 0
    return yeardiff <= 1 ? -1 : 1
}

const iframe = function(dom, url) {
    const iframes = dom.getElementsByTagName('iframe')
    if (iframes.lenght > 0) return -1
    else return 1
}

const popupwindow = function(dom, url) {
    const html = dom.documentElement.innerHTML
    if (html.indexOf('window.prompt') === -1) return 1
    else -1
}

const rightclick = function(dom, url) {
    const html = dom.documentElement.innerHTML

    const re = new RegExp('event.button *== *2')
    if (re.test(html)) return -1
    else return 1
}

const on_mouseover = function(dom, url) {
    return 1
}

const submitting_to_email = function(dom, url) {
    const isMailTo = x => x.indexOf('mailto') !== -1
    const forms = Array.prototype.slice
                       .call(dom.getElementsByTagName('form'))
                       .map(s => s.action)

    const $forms = forms.filter(isMailTo)
    if ($forms.lenght > 0) return -1
    else return 1
}

const sfh = function(dom, url) {
    const sameDomainUrl = sameDomain(url)
    const ifDomainForm = src => pattern.match(src).domain === undefined || sameDomainUrl(src)

    const forms = Array.prototype.slice
                       .call(dom.getElementsByTagName('form'))
                       .map(s => s.action)

    const domain_forms = forms.filter(ifDomainForm)
    const null_forms = forms.filter(s => s)
    if (null_forms.length > 0) return -1
    else if ((forms.length - domain_forms.length) > 0) return 0
    else return 1
}

const link_in_tags = function(dom, url) {
    const sameDomainUrl = sameDomain(url)
    const links = Array.prototype.slice
                       .call(dom.getElementsByTagName('link'))
                       .filter(s => s.href)
                       .map(s => s.href)

    const scripts = Array.prototype.slice
                         .call(dom.getElementsByTagName('script'))
                         .filter(s => s.src)
                         .map(s => s.src)

    const $links = links.filter(sameDomainUrl)
    const $scripts = scripts.filter(sameDomainUrl)
    const link_ratio = (links.length - $links.length)/links.length
    const script_ratio = (scripts.length - $scripts.length)/scripts.length

    const ratio = (link_ratio + script_ratio)/2 | 0
    console.log(ratio)
    if (ratio < 0.17) return 1
    else if (ratio >= 0.17 && ratio <= 0.81) return 0
    else return -1
}

const url_of_anchor = function(dom, url) {
    const sameDomainUrl = sameDomain(url)
    const anchors = Array.prototype.slice
                         .call(dom.getElementsByTagName('a'))
                         .filter(s => s.href)
                         .map(s => s.href)

    const $anchors = anchors.filter(sameDomainUrl)

    const req_ratio = (anchors.length - $anchors.length)/anchors.length
    if (req_ratio < 0.31) return 1
    else if (req_ratio >= 0.31 && req_ratio < 0.67) return 0
    else return -1
}

const request_url = function(dom, url) {
    const sameDomainUrl = sameDomain(url)
    const imgs = Array.prototype.slice
                      .call(dom.getElementsByTagName('img'))
                      .filter(s => s.src)
                      .map(s => s.src)
    const $imgs = imgs.filter(sameDomainUrl)
    const req_ratio = (imgs.length - $imgs.length)/imgs.length | 0
    if (req_ratio < 0.22) return 1
    else if (req_ratio >= 0.22 && req_ratio < 0.61) return 0
    else return -1
}

const https_token = function(url) {
    const domain = pattern.match(url).domain
    if (domain.indexOf('https') === -1) return 1
    else return -1
}

const port = async function(url) {
    const { ports } = await nodePortScanner(url, [21, 22, 23, 80, 443, 445, 1433, 1521, 3306, 3389])
    if (ports.open.lenght === 2 && ports.close.lenght === 8) return 1
    else -1
}

const isFavicon = object => object.type === 'image/x-icon'

const favicon = async function(url) {
    const { icons } = await getWebsiteFavicon(url)
    const favicon = icons.find(isFavicon)
    const favicon_domain = pattern.match(favicon.src).domain
    const url_domain = pattern.match(url).domain

    if (favicon_domain === url_domain) return 1
    else -1
}

const ssl_state = function(url) {
    return new Promise((resolve, reject) => {
        if (pattern.match(url).protocol === 'https') {
            const options = {
                host: url,
                method: 'get',
            }
            const req = https.request(
                options,
                function (res, error) {
                    if (error) reject(error)
                    else if (res.socket.authorized) resolve(1)
                    else resolve(0)
                })
            req.end();
        }
        else resolve(-1)
    })
}

const getExpireDate = function(info) {
    const value = info['Registry Expiry Date']
    return value
}

const domain_registeration_length = function(info) {
    const current_date = new Date()
    const expiration_date = getExpireDate(info)

    const yeardiff = expiration_date ? yearDiff(current_date, new Date(expiration_date)) : 0
    return yeardiff <= 1 ? -1 : 1
}

const shortining_service = function(url) {
    return new Promise((resolve, reject) => {
        fetch(url).then(function(res){
            if (res.status == 302) {
                resolve(-1)
            }
            else {
                resolve(1)
            }
        })
    })
}

const url_length = function(url) {
    const len = url.length
    if (len < 54) return 1
    else if (len > 54 && len <= 75) return 0
    else return -1
}

const having_ip_address = function(url) {
    if (isIp(url)) return -1
    else return 1
}

const getFeatures = async function(input) {
    const url = normalizeUrl(input, {forceHttps: true})
    const info = await WhoisLight.lookup({ format: true }, input)
    const dom = await getSourceAsDOM(url)
    var list = Array.of(30).fill(1)
    //HAVING IP ADDRESS
    list[0] = having_ip_address(url)
    //URL LENGHT
    list[1] = url_length(url)
    //SHORTINING SERVICE
    list[2] = await shortining_service(url)
    //HAVING AT SYMBOL
    if (url.includes('@')) {
        list[3] = -1
    } else {
        list[3] = 1
    }
    //DOUBLE SLASH REDIRECTING
    if (url.indexOf('//') > 6) {
        list[4] = -1
    } else {
        list[4] = 1
    }
    //PREFIX SUFFIX
    let hostname = (new URL(url)).hostname;
    if (hostname.includes('-')) {
        list[5] = -1
    } else {
        list[5] = 1
    }
    //HAVING SUB DOMAIN
    const charCount = (char, str) => str.split(char).length - 1
    if (charCount('.', url) === 1) {
        list[6] = 1
    } else if (charCount('.', url) === 2) {
        list[6] = 0
    } else {
        list[6] = -1
    }
    //SSLFINAL STATE
    list[7] = 1//await ssl_state(url)
    //DOMAIN_REGISTERATION_LENGTH
    list[8] = domain_registeration_length(info)
    //FAVICON
    list[9] = await favicon(url)
    //PORT
    list[10] = 1//await port(url)
    //HTTPS_TOKEN
    list[11] = https_token(url)
    //REQUEST_URL
    list[12] = request_url(dom, url)
    //URL_OF_ANCHOR
    list[13] = url_of_anchor(dom, url)
    //LINKS_IN_TAGS
    list[14] = link_in_tags(dom, url)
    //SFH
    list[15] = sfh(dom, url)
    //SUBMITTING_TO_EMAIL
    list[16] = submitting_to_email(dom, url)
    //ABNORMAL_URL
    list[17] = isIp(url) ? -1 : 1
    //REDIRECT
    list[18] = 0
    //ON_MOUSEOVER
    list[19] = on_mouseover(dom, url)
    //RIGHTCLICK
    list[20] = rightclick(dom, url)
    //POPUPWINDOW
    list[21] = popupwindow(dom, url)
    //IFRAME
    list[22] = iframe(dom, url)
    //AGE_OF_DOMAIN
    list[23] = age_of_domain(info)
    //DNSRECORD
    list[24] = await dnsrecord(url)
    //WEB_TRAFFIC
    list[25] = web_traffic(url)
    //PAGE_RANK
    list[26] = page_rank(url)
    //GOOGLE_INDEX
    list[27] = google_index(url)
    //LINKS_POINTING_TO_PAGE
    list[28] = links_pointing_to_page(url)
    //STATISTICAL_REPORT
    list[29] = statistical_report(url)
    return list
}

export default getFeatures
