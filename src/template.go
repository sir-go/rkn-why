package main

const pageTmpl = `<!DOCTYPE html> <html lang="ru"> <head> <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1"> <title>РКН?</title> <style> #title { font-size: 16pt; font-family: sans-serif; text-align: center; color: darkgrey; } body { padding: 3vmin; max-width: 45rem; } form { display: flex; flex-direction: row; flex-wrap: wrap; margin-top: 1rem; } input { padding: .3rem .5rem; margin-top: .3rem; font-size: 1.3rem; } input[name="q"] { flex-grow: 999; border: 1px solid #cecece; } input[type="submit"] { cursor: pointer; flex-shrink: 1; flex-grow: 1; } #out { background: rgba(255, 248, 220, 0.48); margin-top: .7rem; border: 1px solid darkgrey; padding: .5rem .5rem; font-family: monospace; } .green { color: darkgreen; } .red { color: darkred; } .ip { width: 20ex; display: inline-block; background: white; } .domain { background: white; border: 1px solid #f3f3f3; word-wrap: break-word; } p { margin: .3rem 0; } #rem { padding: 1rem; font-family: monospace; color: #444444; line-height: 1.4; } #rem ul { padding-left: 1rem; } #rem li { margin: .5rem 0; line-height: 1.4; } </style> </head> <body> <div id="title">блокируется ли ресурс Роскомнадзором</div> <form action="/" method="get"> <input name="q" type="text" value="{{ query }}" placeholder="IP адрес или URL ресурса" required autofocus autocorrect="off" autocapitalize="off" spellcheck="false" /> <input type="submit" value="проверить" /> </form> {% if query %} <div id="out"> {% if error %}<span class="red">{{error}}</span> {% else %} {% if queryIsIp %} IP:<br/> {% if blockedSubnet %} <p> <span class="ip">{{ query }}</span> {% if blockedSubnet.Amount > 1 %} <b class="red">в базе - вся подсеть {{ blockedSubnet.SubNet }}</b><br/> это {{ blockedSubnet.Amount }} IP в диапазоне {{ blockedSubnet.MinIP }}-{{ blockedSubnet.MaxIP }} {% else %} <b class="red">есть базе</b> {% endif %} {% else %} <span class="ip">{{ query }}</span> <b class="green">доступен</b> </p> {% endif %} {% else %} IP:<br/> {% for ip in checkedIPs %} <div class="ip">{{ ip.String() }}</div> {% if forloop.Last and blockedSubnet %} {% if blockedSubnet.Amount > 1 %} <b class="red">в базе - вся подсеть {{ blockedSubnet.SubNet }}</b><br/> это {{ blockedSubnet.Amount }} IP в диапазоне {{ blockedSubnet.MinIP }}-{{ blockedSubnet.MaxIP }} {% else %} <b class="red">есть базе</b> {% endif %} {% else %} <b class="green">нет в базе</b> {% endif %}<br/> {% empty %} <span class="red">не дождались ответа DNS</span> {% endfor %} {% endif %} {% if !blockedSubnet %} <hr/> {% if blockedDomains %} <span class="red"><b>домены в базе:</b></span><br/> {% for domain in blockedDomains %} <p><span class="domain">{{ domain }}</span></p> {% endfor %} {% else %} домен: <b class="green">нет в базе</b><br/> {% endif %} {% endif %} {% if !blockedSubnet and !blockedDomains %} <hr/> {% if blockedUrls %} <span class="red"><b>ресурсы хоста в базе:</b></span><br/> {% for url in blockedUrls %} <p><span class="domain">http://{{ url }}</span></p> {% endfor %} {% else %} ресурсы на домене: <b class="green">нет в базе</b><br/> {% endif %} {% endif %} {% endif %} </div> {% if !error and !blockedSubnet and !blockedDomains and !blockedUrls %} <div id="rem"> <p>Если ресурса нет в базе заблокированных, но Вам не доступен, то возможны следующие варианты:</p> <ul type="square"> {% if !queryIsIp %} <li> DNS вернул не все возможные IP адреса - если это облачный сервис и нагрузка на нём балансируется между разными серверами на одном домене, то IP адреса доступных серверов могут меняться с каждым запросом. <br/> Проверенные сейчас адреса могут отличаться от тех, которые получаете Вы при обращении к ресурсу. <br/> Если Вам известен конкретный IP адрес сервера, лучше проверьте его. </li> {% endif %} <li> ресурс блокируется вышестоящим провайдером - на маршруте от Вас до сервера - несколько участков сети, контролируемых разными провайдерами связи, отсутствие блокировки у Вашего провайдера не гарантирует её отсутствие у провайдера выше </li> <li> нестандартные настройки сети: в Вашей ОС настроены сторонние DNS, VPN или Proxy, также в доступность ресурсов могут вмешиваться антивирусы и фаерволы </li> <li> ресурс упал, проверьте доступность ресурса через мобильный Интернет и/или сервисами доступности сайтов из разных национальных зон, например <a href="https://www.uptrends.com/tools/uptime">uptrends.com</a> или <a href="https://2ip.ru/site-availability/">2ip.ru</a> </li> </ul> </div> {% endif %} {% endif %} </body> </html>`
