/* 
 * Easy Share Buttons
 *
 * @author ml
 */
;;;
(function () {
	var settings = {
			"selector": ".easy-share",
			"attr": {
				"services": "data-services",
				"url": "data-url"
			}
		},
		services = {
		"vkontakte" : {
			"title": "ВКонтакте",
			"url": "https://vk.com/share.php",
			"attr": {
				"url": "url",
				"title": "title"
			},
			"background": {
				"color": "#4680c2",
				"image": "data:image/svg+xml,%3Csvg viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M19.623 7.66c.12-.372 0-.643-.525-.643h-1.745c-.44 0-.644.237-.763.491 0 0-.898 2.17-2.152 3.576-.406.406-.593.542-.813.542-.119 0-.271-.136-.271-.508V7.644c0-.44-.136-.644-.509-.644H10.1c-.27 0-.44.203-.44.407 0 .423.627.525.694 1.711v2.576c0 .559-.101.66-.322.66-.593 0-2.033-2.185-2.897-4.676-.17-.492-.339-.678-.78-.678H4.593C4.085 7 4 7.237 4 7.491c0 .458.593 2.762 2.762 5.813 1.44 2.084 3.49 3.202 5.338 3.202 1.118 0 1.254-.254 1.254-.678v-1.575c0-.509.101-.594.457-.594.254 0 .712.136 1.746 1.136 1.186 1.186 1.39 1.728 2.05 1.728h1.745c.509 0 .746-.254.61-.745-.152-.492-.728-1.203-1.474-2.05-.407-.475-1.017-1-1.203-1.255-.254-.339-.186-.474 0-.78-.017 0 2.118-3.015 2.338-4.032' fill='%23FFF' fill-rule='evenodd'/%3E%3C/svg%3E"
			}
		},
		"facebook": {
			"title": "Facebook",
			"url": "https://www.facebook.com/sharer.php?src=sp",
			"attr": {
				"url": "u",
				"title": "title"
			},
			"background": {
				"color": "#3b5998",
				"image": "data:image/svg+xml,%3Csvg viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M13.423 20v-7.298h2.464l.369-2.845h-2.832V8.042c0-.824.23-1.385 1.417-1.385h1.515V4.111A20.255 20.255 0 0014.148 4c-2.183 0-3.678 1.326-3.678 3.76v2.097H8v2.845h2.47V20h2.953z' fill='%23FFF' fill-rule='evenodd'/%3E%3C/svg%3E"
			}
		},
		"odnoklassniki": {
			"title": "Одноклассники",
			"url": "https://connect.ok.ru/offer",
			"attr": {
				"url": "url",
				"title": "title"
			},
			"background": {
				"color": "#eb722e",
				"image": "data:image/svg+xml,%3Csvg viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M11.674 6.536a1.69 1.69 0 00-1.688 1.688c0 .93.757 1.687 1.688 1.687a1.69 1.69 0 001.688-1.687 1.69 1.69 0 00-1.688-1.688zm0 5.763a4.08 4.08 0 01-4.076-4.075 4.08 4.08 0 014.076-4.077 4.08 4.08 0 014.077 4.077 4.08 4.08 0 01-4.077 4.075zm-1.649 3.325a7.633 7.633 0 01-2.367-.98 1.194 1.194 0 011.272-2.022 5.175 5.175 0 005.489 0 1.194 1.194 0 111.272 2.022 7.647 7.647 0 01-2.367.98l2.279 2.28a1.194 1.194 0 01-1.69 1.688l-2.238-2.24-2.24 2.24a1.193 1.193 0 11-1.689-1.689l2.279-2.279' fill='%23FFF' fill-rule='evenodd'/%3E%3C/svg%3E"
			}
		},
		"twitter": {
			"title": "Twitter",
			"url": "https://twitter.com/intent/tweet",
			"attr": {
				"url": "url",
				"title": "text"
			},
			"background": {
				"color": "#00aced",
				"image": "data:image/svg+xml,%3Csvg viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M20 7.539a6.56 6.56 0 01-1.885.517 3.294 3.294 0 001.443-1.816 6.575 6.575 0 01-2.085.796 3.283 3.283 0 00-5.593 2.994A9.32 9.32 0 015.114 6.6a3.28 3.28 0 001.016 4.382 3.274 3.274 0 01-1.487-.41v.041a3.285 3.285 0 002.633 3.218 3.305 3.305 0 01-1.482.056 3.286 3.286 0 003.066 2.28A6.585 6.585 0 014 17.524 9.291 9.291 0 009.032 19c6.038 0 9.34-5 9.34-9.337 0-.143-.004-.285-.01-.425A6.672 6.672 0 0020 7.538z' fill='%23FFF' fill-rule='evenodd'/%3E%3C/svg%3E"
			}
		},
		"common_styles": ".easy-share-badge {display: inline-block; border-radius: 4px; color: #fff; overflow: hidden; position: relative; height: 24px; width: 24px; background-size: 24px 24px; vertical-align: top; padding: 0; margin: 2px 4px 0 0;} "
	};
	document.addEventListener("DOMContentLoaded", function () {

		var elements = document.querySelectorAll(settings.selector), styles=[];

		for(var i=0; i<elements.length; i++) {
			var list = elements[i].getAttribute(settings.attr.services).split(','), url=elements[i].getAttribute(settings.attr.url);
			for( var k=0; k<list.length;k++ ) {
				if ( !!!services[list[k]] ) continue;
				var a = document.createElement('a');
				a.href = services[list[k]].url
						+ ((services[list[k]].url.indexOf('?')+1)?'&':'?')
						+ services[list[k]].attr.url + '=' + encodeURIComponent(url)
						+ '&' + services[list[k]].attr.title + '=' + encodeURIComponent(document.title);
				a.title = services[list[k]].title;
				a.rel = "nofollow noopener";
				a.target = "_blank";
				a.className = 'easy-share-badge easy-share-' + list[k];
				elements[i].appendChild(a);
				styles.push(
					'.easy-share-' + list[k]
					+ '{background-color:'
					+ services[list[k]].background.color
					+ ';background-image:url("'
					+ services[list[k]].background.image
					+ '");}'
				);
			}
		}
		var s = document.createElement('style');
		s.type = 'text/css';
		s.innerHTML =  services.common_styles + styles.join(' ');
		document.getElementsByTagName('HEAD')[0].appendChild(s);
	});
})();
