const config = {
  no_ref: "off", //控制HTTP Referer头部，如果您想创建一个匿名链接以隐藏HTTP Referer头部，请设置为"on"。
  theme:"theme/captcha",//首页主题，使用空值表示默认主题。要使用urlcool主题，请填写"theme/urlcool"。如果需要验证码功能，需要使用captcha主题。
  cors: "on",//允许API请求的跨域资源共享。
  unique_link:true,//如果为true，相同的长网址将生成相同的短网址
  custom_link:false,//允许用户自定义短网址。
  safe_browsing_api_key: "", //输入Google安全浏览API密钥以在重定向前启用网址安全检查。
  
  // 验证码配置
  captcha: {
    enabled: true, // 验证码服务主开关
    api_endpoint: "https://captcha.gurl.eu.org/api", // CAP Worker API端点
    require_on_create: true, // 创建短链接时需要验证码
    require_on_access: true, // 访问短链接时需要验证码
    timeout: 5000, // API请求超时时间（毫秒）
    fallback_on_error: true, // 当验证码服务不可用时允许操作
    max_retries: 2, // 验证码API调用的最大重试次数
  }
  }
  
  const html404 = `<!DOCTYPE html>
  <body>
    <h1>404 未找到。</h1>
    <p>您访问的网址不存在。</p>
    <a href="https://github.com/Cakjew/Url-Shorten-Chinese" target="_self">在GitHub上Fork我</a>
  </body>`
  
  let response_header={
    "content-type": "text/html;charset=UTF-8",
  } 
  
  if (config.cors=="on"){
    response_header={
    "content-type": "text/html;charset=UTF-8",
    "Access-Control-Allow-Origin":"*",
    "Access-Control-Allow-Methods": "POST",
    }
  }
  
  async function randomString(len) {
  　　len = len || 6;
  　　let $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';    /****默认去掉了容易混淆的字符oOLl,9gq,Vv,Uu,I1****/
  　　let maxPos = $chars.length;
  　　let result = '';
  　　for (let i = 0; i < len; i++) {
  　　　　result += $chars.charAt(Math.floor(Math.random() * maxPos));
  　　}
  　　return result;
  }
  
  async function sha512(url){
      url = new TextEncoder().encode(url)
  
      const url_digest = await crypto.subtle.digest(
        {
          name: "SHA-512",
        },
        url, // The data you want to hash as an ArrayBuffer
      )
      const hashArray = Array.from(new Uint8Array(url_digest)); // convert buffer to byte array
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      //console.log(hashHex)
      return hashHex
  }
  async function checkURL(URL){
      let str=URL;
      let Expression=/http(s)?:\/\/([\w-]+\.)+[\w-]+(\/[\w- .\/?%&=]*)?/;
      let objExp=new RegExp(Expression);
      if(objExp.test(str)==true){
        if (str[0] == 'h')
          return true;
        else
          return false;
      }else{
          return false;
      }
  } 
  async function save_url(URL){
      let random_key=await randomString()
      let is_exist=await LINKS.get(random_key)
      console.log(is_exist)
      if (is_exist == null)
          return await LINKS.put(random_key, URL),random_key
      else
          return save_url(URL)
  }
  async function is_url_exist(url_sha512){
    let is_exist = await LINKS.get(url_sha512)
    console.log(is_exist)
    if (is_exist == null) {
      return false
    }else{
      return is_exist
    }
  }
  async function is_url_safe(url){
  
    let raw = JSON.stringify({"client":{"clientId":"Url-Shorten-Worker","clientVersion":"1.0.7"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","POTENTIALLY_HARMFUL_APPLICATION","UNWANTED_SOFTWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":url}]}});
  
    let requestOptions = {
      method: 'POST',
      body: raw,
      redirect: 'follow'
    };
  
    let result = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+config.safe_browsing_api_key, requestOptions)
    result = await result.json()
    console.log(result)
    if (Object.keys(result).length === 0){
      return true
    }else{
      return false
    }
  }
  
  // ============ 验证码服务集成 ============
  
  /**
   * 使用重试和回退机制验证验证码令牌
   * @param {string} token - 要验证的验证码令牌
   * @param {boolean} keepToken - 是否保留令牌以供重复使用
   * @returns {Promise<{success: boolean, error?: string, degraded?: boolean}>}
   */
  async function validateCaptchaToken(token, keepToken = false) {
    // 如果验证码已禁用，始终返回成功
    if (!config.captcha.enabled) {
      return { success: true, degraded: false };
    }
  
    // 验证令牌格式
    if (!token || typeof token !== 'string' || token.length < 10) {
      return { success: false, error: '无效的令牌格式' };
    }
  
    let lastError = null;
    const maxRetries = config.captcha.max_retries || 2;
  
    // 弹性重试机制
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.captcha.timeout);
  
        const response = await fetch(`${config.captcha.api_endpoint}/validate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Url-Shorten-Worker/1.0.7',
          },
          body: JSON.stringify({ token, keepToken }),
          signal: controller.signal,
        });
  
        clearTimeout(timeoutId);
  
        // 处理各种HTTP状态码
        if (response.ok) {
          const result = await response.json();
          return { success: result.success === true, degraded: false };
        }
  
        // 处理特定错误代码
        if (response.status === 400 || response.status === 410 || response.status === 404 || response.status === 409) {
          // 客户端错误，无需重试
          return { success: false, error: '无效或过期的令牌' };
        }
  
        lastError = `HTTP ${response.status}`;
      } catch (error) {
        lastError = error.name === 'AbortError' ? '超时' : error.message;
        console.error(`验证码验证尝试 ${attempt + 1} 失败:`, lastError);
  
        // 重试前的指数退避（最后一次尝试除外）
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 100));
        }
      }
    }
  
    // 服务降级：如果启用了回退，则允许操作
    if (config.captcha.fallback_on_error) {
      console.warn(`验证码服务降级: ${lastError}。由于回退策略，允许操作。`);
      return { success: true, degraded: true };
    }
  
    return { success: false, error: lastError || '验证码服务不可用' };
  }
  
  /**
   * 检查当前操作是否需要验证码
   * @param {string} operation - 'create' 或 'access'
   * @returns {boolean}
   */
  function isCaptchaRequired(operation) {
    if (!config.captcha.enabled) {
      return false;
    }
  
    switch (operation) {
      case 'create':
        return config.captcha.require_on_create;
      case 'access':
        return config.captcha.require_on_access;
      default:
        return false;
    }
  }
  
  /**
   * 从请求中提取验证码令牌
   * @param {Request} request - 传入的请求
   * @returns {Promise<string|null>}
   */
  async function extractCaptchaToken(request) {
    const contentType = request.headers.get('content-type') || '';
  
    if (contentType.includes('application/json')) {
      try {
        const body = await request.clone().json();
        return body.captcha_token || body.captchaToken || body.token || null;
      } catch {
        return null;
      }
    }
  
    // 尝试从URL参数中提取
    const url = new URL(request.url);
    return url.searchParams.get('captcha_token') || url.searchParams.get('token') || null;
  }
  
  // ============ 验证码服务集成结束 ============
  async function handleRequest(request) {
    console.log(request)
    
    // 处理POST请求 - 创建短链接
    if (request.method === "POST") {
      let req = await request.json()
      console.log(req["url"])
      
      // 验证URL格式
      if (!await checkURL(req["url"])) {
        return new Response(JSON.stringify({
          status: 500,
          error: "无效的URL格式"
        }), {
          headers: response_header,
          status: 400
        })
      }
  
      // 链接创建的验证码验证
      if (isCaptchaRequired('create')) {
        const captchaToken = req.captcha_token || req.captchaToken || req.token;
        
        if (!captchaToken) {
          return new Response(JSON.stringify({
            status: 403,
            error: "需要验证码令牌",
            captcha_required: true
          }), {
            headers: response_header,
            status: 403
          })
        }
  
        const validation = await validateCaptchaToken(captchaToken, false);
        
        if (!validation.success) {
          return new Response(JSON.stringify({
            status: 403,
            error: validation.error || "验证码验证失败",
            captcha_required: true
          }), {
            headers: response_header,
            status: 403
          })
        }
  
        // 如果服务降级，记录日志
        if (validation.degraded) {
          console.warn("在验证码服务降级情况下处理请求");
        }
      }
  
      // 处理短链接创建
      let stat, random_key
      if (config.unique_link) {
        let url_sha512 = await sha512(req["url"])
        let url_key = await is_url_exist(url_sha512)
        if (url_key) {
          random_key = url_key
        } else {
          stat, random_key = await save_url(req["url"])
          if (typeof(stat) == "undefined") {
            console.log(await LINKS.put(url_sha512, random_key))
          }
        }
      } else {
        stat, random_key = await save_url(req["url"])
      }
      
      console.log(stat)
      if (typeof(stat) == "undefined") {
        return new Response(JSON.stringify({
          status: 200,
          key: "/" + random_key,
          short_url: "/" + random_key
        }), {
          headers: response_header,
        })
      } else {
        return new Response(JSON.stringify({
          status: 500,
          error: "达到KV写入限制"
        }), {
          headers: response_header,
          status: 500
        })
      }
    } else if (request.method === "OPTIONS") {  
      return new Response("", {
        headers: response_header,
      })
    }
  
    // 处理GET请求 - 访问短链接
    const requestURL = new URL(request.url)
    const path = requestURL.pathname.split("/")[1]
    const params = requestURL.search
  
    console.log(path)
    
    // 提供首页
    if (!path) {
      const html = await fetch("https://cakjew.github.io/Url-Shorten-Chinese/index.html")
      
      return new Response(await html.text(), {
        headers: {
          "content-type": "text/html;charset=UTF-8",
        },
      })
    }
  
    // 检索目标URL
    const value = await LINKS.get(path)
    let location
  
    if (params) {
      location = value + params
    } else {
      location = value
    }
    console.log(value)
  
    if (location) {
      // 链接访问的验证码验证
      if (isCaptchaRequired('access')) {
        const captchaToken = await extractCaptchaToken(request)
        
        if (!captchaToken) {
          // 返回验证码挑战页面
          const captchaPage = `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>需要验证</title>
    <script src="https://captcha.gurl.eu.org/cap.min.js"></script>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; 
             display: flex; justify-content: center; align-items: center; min-height: 100vh; 
             margin: 0; background: linear-gradient(45deg, rgba(14, 46, 75, 1.000) 0.000%, rgba(14, 46, 75, 1.000) 7.692%, rgba(19, 52, 84, 1.000) 7.692%, rgba(19, 52, 84, 1.000) 15.385%, rgba(25, 58, 94, 1.000) 15.385%, rgba(25, 58, 94, 1.000) 23.077%, rgba(31, 65, 104, 1.000) 23.077%, rgba(31, 65, 104, 1.000) 30.769%, rgba(38, 72, 115, 1.000) 30.769%, rgba(38, 72, 115, 1.000) 38.462%, rgba(45, 79, 126, 1.000) 38.462%, rgba(45, 79, 126, 1.000) 46.154%, rgba(52, 86, 138, 1.000) 46.154%, rgba(52, 86, 138, 1.000) 53.846%, rgba(59, 93, 150, 1.000) 53.846%, rgba(59, 93, 150, 1.000) 61.538%, rgba(67, 101, 163, 1.000) 61.538%, rgba(67, 101, 163, 1.000) 69.231%, rgba(75, 109, 176, 1.000) 69.231%, rgba(75, 109, 176, 1.000) 76.923%, rgba(83, 117, 188, 1.000) 76.923%, rgba(83, 117, 188, 1.000) 84.615%, rgba(91, 125, 201, 1.000) 84.615%, rgba(91, 125, 201, 1.000) 92.308%, rgba(99, 134, 214, 1.000) 92.308% 100.000%) }
      .container { background: white; padding: 2rem; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.1); 
                   max-width: 400px; text-align: center; }
      h1 { color: #333; margin-bottom: 1rem; font-size: 1.5rem; }
      p { color: #666; margin-bottom: 2rem; }
      #cap { margin: 2rem 0; display: flex; justify-content: center;}
      .loading { display: none; color: #667eea; margin-top: 1rem; }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>🔒 需要验证</h1>
      <p>请完成下方的验证码以访问此链接。</p>
      
      <cap-widget id="cap" data-cap-api-endpoint="https://captcha.gurl.eu.org/api/"></cap-widget>
      
      <div class="loading" id="loading">验证中，即将重定向...</div>
    </div>
  
    <script>
      const widget = document.querySelector("#cap");
      const loading = document.getElementById("loading");
      
      widget.addEventListener("solve", async function (e) {
        const token = e.detail.token;
        loading.style.display = "block";
        
        // 使用令牌重定向
        window.location.href = window.location.pathname + "?captcha_token=" + encodeURIComponent(token);
      });
    </script>
  </body>
  </html>`
          
          return new Response(captchaPage, {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
            status: 403
          })
        }
  
        const validation = await validateCaptchaToken(captchaToken, false)
        
        if (!validation.success) {
          return new Response(`
  <!DOCTYPE html>
  <html>
  <head><title>验证失败</title></head>
  <body>
    <h1>❌ 验证失败</h1>
    <p>${validation.error || '验证码验证失败'}</p>
    <a href="${requestURL.pathname}">重试</a>
  </body>
  </html>`, {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
            status: 403
          })
        }
  
        if (validation.degraded) {
          console.warn("在验证码服务降级情况下允许访问")
        }
      }
  
      // 安全浏览检查
      if (config.safe_browsing_api_key) {
        if (!(await is_url_safe(location))) {
          let warning_page = await fetch("https://xytom.github.io/Url-Shorten-Worker/safe-browsing.html")
          warning_page = await warning_page.text()
          warning_page = warning_page.replace(/{Replace}/gm, location)
          return new Response(warning_page, {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
          })
        }
      }
  
      // 重定向到目标URL
      if (config.no_ref == "on") {
        let no_ref = await fetch("https://xytom.github.io/Url-Shorten-Worker/no-ref.html")
        no_ref = await no_ref.text()
        no_ref = no_ref.replace(/{Replace}/gm, location)
        return new Response(no_ref, {
          headers: {
            "content-type": "text/html;charset=UTF-8",
          },
        })
      } else {
        return Response.redirect(location, 302)
      }
    }
    
    // 如果KV中不存在请求，返回404
    return new Response(html404, {
      headers: {
        "content-type": "text/html;charset=UTF-8",
      },
      status: 404
    })
  }
  
  addEventListener("fetch", async event => {
    event.respondWith(handleRequest(event.request))
  })