(window.webpackJsonp = window.webpackJsonp || []).push([
    [15, 10], {
        502: function(t, e, r) {
            "use strict";
            r.r(e);
            var n = r(514),
                o = {
                    methods: {
                        errorInfo: function() {
                            return this.error.response ? this.error.response.data.message : this.error
                        }
                    },
                    props: ["error"]
                },
                l = r(71),
                component = Object(l.a)(o, (function() {
                    var t = this,
                        e = t._self._c;
                    return t.error ? e(n.a, {
                        staticClass: "mt-5",
                        attrs: {
                            border: "right",
                            dense: "",
                            "colored-border": "",
                            type: "error",
                            elevation: "2"
                        }
                    }, [t._v("\n  " + t._s(t.errorInfo()) + "\n")]) : t._e()
                }), [], !1, null, null, null);
            e.default = component.exports
        },
        503: function(t, e, r) {
            "use strict";
            r.r(e);
            var n = r(224),
                o = r(531),
                l = {
                    props: ["submitForm", "submitText", "formData"],
                    components: {
                        DisplayError: r(502).default
                    },
                    data: function() {
                        return {
                            error: null,
                            valid: null
                        }
                    },
                    methods: {
                        submit: function() {
                            var t = this;
                            this.error = null, this.submitForm(this.formData).catch((function(e) {
                                return t.error = e
                            }))
                        }
                    }
                },
                c = r(71),
                component = Object(c.a)(l, (function() {
                    var t = this,
                        e = t._self._c;
                    return e("div", [e(o.a, {
                        staticClass: "mt-10",
                        model: {
                            value: t.valid,
                            callback: function(e) {
                                t.valid = e
                            },
                            expression: "valid"
                        }
                    }, [t._t("default"), t._v(" "), e(n.a, {
                        staticClass: "mt-2",
                        attrs: {
                            disabled: !t.valid,
                            type: "submit",
                            block: ""
                        },
                        on: {
                            click: function(e) {
                                return e.preventDefault(), t.submit.apply(null, arguments)
                            }
                        }
                    }, [t._v(t._s(t.submitText))])], 2), t._v(" "), e("DisplayError", {
                        attrs: {
                            error: t.error
                        }
                    })], 1)
                }), [], !1, null, null, null);
            e.default = component.exports
        },
        504: function(t, e, r) {
            "use strict";
            r(29), r(24);
            e.a = {
                required: function(t) {
                    return function(e) {
                        return e && e.length > 0 || "Field ".concat(t, " is required")
                    }
                },
                email: function(t) {
                    var e = /^[A-Z0-9+_.-]+@[A-Z0-9.-]+$/i;
                    return function(r) {
                        return r && e.test(r) || "Field ".concat(t, " must be a valid email")
                    }
                },
                url: function(t) {
                    var e = /^https?:\/\/[a-z0-9+_.-]+\//;
                    return function(r) {
                        return r && e.test(r) || "Field ".concat(t, " must be a valid url")
                    }
                },
                maxlen: function(t, e) {
                    return function(r) {
                        return r && r.length < e || "Field ".concat(t, " has a ").concat(e, " character limit")
                    }
                },
                alphaNum: function(t) {
                    var e = /^[[A-Z0-9-_]+$/i;
                    return function(r) {
                        return r && e.test(r) || "Field ".concat(t, " must be a alpha or num only")
                    }
                }
            }
        },
        523: function(t, e, r) {
            "use strict";
            r.r(e);
            var n = r(224),
                o = r(498),
                l = r(501),
                c = r(488),
                m = r(218),
                f = r(520),
                d = r(568),
                v = r(83),
                h = r(532),
                y = r(527),
                D = r(556),
                _ = (r(25), r(11), r(10), r(15), r(16), r(8), r(5), r(9), r(2)),
                x = (r(151), r(503)),
                O = r(504);

            function k(t, e) {
                var r = Object.keys(t);
                if (Object.getOwnPropertySymbols) {
                    var n = Object.getOwnPropertySymbols(t);
                    e && (n = n.filter((function(e) {
                        return Object.getOwnPropertyDescriptor(t, e).enumerable
                    }))), r.push.apply(r, n)
                }
                return r
            }

            function j(t) {
                for (var e = 1; e < arguments.length; e++) {
                    var r = null != arguments[e] ? arguments[e] : {};
                    e % 2 ? k(Object(r), !0).forEach((function(e) {
                        Object(_.a)(t, e, r[e])
                    })) : Object.getOwnPropertyDescriptors ? Object.defineProperties(t, Object.getOwnPropertyDescriptors(r)) : k(Object(r)).forEach((function(e) {
                        Object.defineProperty(t, e, Object.getOwnPropertyDescriptor(r, e))
                    }))
                }
                return t
            }
            var $ = {
                    name: "IntegrationForm",
                    components: {
                        SimpleForm: x.default
                    },
                    data: function() {
                        return j({
                            formData: j({
                                active: !1,
                                headers: []
                            }, this.defaultData)
                        }, O.a)
                    },
                    methods: {
                        addHeader: function() {
                            this.formData.headers.push({
                                name: "Header",
                                value: "Value"
                            })
                        },
                        removeHeader: function(t) {
                            this.formData.headers.splice(t, 1)
                        }
                    },
                    props: {
                        types: {
                            default: function() {
                                return ["api", "mail"]
                            }
                        },
                        methods: {
                            default: function() {
                                return ["GET", "POST"]
                            }
                        },
                        submitForm: {},
                        submitText: {},
                        defaultData: {
                            default: function() {
                                return {
                                    type: "api"
                                }
                            }
                        }
                    }
                },
                w = r(71),
                component = Object(w.a)($, (function() {
                    var t = this,
                        e = t._self._c;
                    return e(v.a, {
                        staticClass: "mx-auto",
                        attrs: {
                            width: "500"
                        }
                    }, [e("h1", [t._v("Integration form")]), t._v(" "), e("SimpleForm", {
                        attrs: {
                            submitText: t.submitText,
                            submitForm: t.submitForm,
                            formData: t.formData
                        }
                    }, [e(h.a, {
                        attrs: {
                            label: "active"
                        },
                        model: {
                            value: t.formData.active,
                            callback: function(e) {
                                t.$set(t.formData, "active", e)
                            },
                            expression: "formData.active"
                        }
                    }), t._v(" "), e(d.a, {
                        attrs: {
                            items: t.types,
                            rules: [t.required("type")],
                            label: "type",
                            dense: ""
                        },
                        model: {
                            value: t.formData.type,
                            callback: function(e) {
                                t.$set(t.formData, "type", e)
                            },
                            expression: "formData.type"
                        }
                    }), t._v(" "), e(y.a, {
                        attrs: {
                            rules: [t.required("title")],
                            label: "title"
                        },
                        model: {
                            value: t.formData.title,
                            callback: function(e) {
                                t.$set(t.formData, "title", e)
                            },
                            expression: "formData.title"
                        }
                    }), t._v(" "), e(c.a, {
                        staticClass: "mt-5"
                    }), t._v(" "), "api" === t.formData.type ? e("div", [e(y.a, {
                        attrs: {
                            rules: [t.required("url"), t.url("url")],
                            label: "url"
                        },
                        model: {
                            value: t.formData.url,
                            callback: function(e) {
                                t.$set(t.formData, "url", e)
                            },
                            expression: "formData.url"
                        }
                    }), t._v(" "), e(d.a, {
                        attrs: {
                            items: t.methods,
                            rules: [t.required("method")],
                            label: "method",
                            dense: ""
                        },
                        model: {
                            value: t.formData.method,
                            callback: function(e) {
                                t.$set(t.formData, "method", e)
                            },
                            expression: "formData.method"
                        }
                    }), t._v(" "), e("h4", [t._v("Headers")]), t._v(" "), e(l.a, [t._l(t.formData.headers, (function(header, i) {
                        return e(f.a, {
                            key: "header_".concat(i)
                        }, [e(o.a, {
                            attrs: {
                                cols: "5"
                            }
                        }, [e(y.a, {
                            attrs: {
                                rules: [t.alphaNum("header_name_".concat(header.name)), t.required("header_name_".concat(header.name))],
                                label: "Header name"
                            },
                            model: {
                                value: header.name,
                                callback: function(e) {
                                    t.$set(header, "name", e)
                                },
                                expression: "header.name"
                            }
                        })], 1), t._v(" "), e(o.a, {
                            attrs: {
                                cols: "5"
                            }
                        }, [e(y.a, {
                            attrs: {
                                rules: [t.required("header_value_".concat(header.name))],
                                label: "Header value"
                            },
                            model: {
                                value: header.value,
                                callback: function(e) {
                                    t.$set(header, "value", e)
                                },
                                expression: "header.value"
                            }
                        })], 1), t._v(" "), e(o.a, {
                            attrs: {
                                cols: "2"
                            }
                        }, [e(n.a, {
                            attrs: {
                                small: ""
                            },
                            on: {
                                click: function(e) {
                                    return e.preventDefault(), t.removeHeader(i)
                                }
                            }
                        }, [e(m.a, {
                            attrs: {
                                color: "primary"
                            }
                        }, [t._v("mdi-minus")])], 1)], 1)], 1)
                    })), t._v(" "), t.formData.headers.length < 10 ? e(f.a, [e(o.a, {
                        staticClass: "text-right",
                        attrs: {
                            cols: "12"
                        }
                    }, [e(n.a, {
                        on: {
                            click: function(e) {
                                return e.preventDefault(), t.addHeader()
                            }
                        }
                    }, [e(m.a, {
                        attrs: {
                            color: "primary"
                        }
                    }, [t._v("mdi-plus")])], 1)], 1)], 1) : t._e()], 2), t._v(" "), "POST" === t.formData.method ? e(l.a, [e(f.a, [e(o.a, {
                        attrs: {
                            cols: "12"
                        }
                    }, [e("i", [t._v("Add a %FORM_RESULT% template that will pass the form results")])]), t._v(" "), e(o.a, {
                        attrs: {
                            cols: "12"
                        }
                    }, [e(D.a, {
                        attrs: {
                            label: "body",
                            dense: ""
                        },
                        model: {
                            value: t.formData.body,
                            callback: function(e) {
                                t.$set(t.formData, "body", e)
                            },
                            expression: "formData.body"
                        }
                    })], 1)], 1)], 1) : t._e()], 1) : e("div", [e(y.a, {
                        attrs: {
                            rules: [t.required("from"), t.email("from")],
                            label: "from"
                        },
                        model: {
                            value: t.formData.from,
                            callback: function(e) {
                                t.$set(t.formData, "from", e)
                            },
                            expression: "formData.from"
                        }
                    }), t._v(" "), e(y.a, {
                        attrs: {
                            rules: [t.required("to"), t.email("to")],
                            label: "to"
                        },
                        model: {
                            value: t.formData.to,
                            callback: function(e) {
                                t.$set(t.formData, "to", e)
                            },
                            expression: "formData.to"
                        }
                    }), t._v(" "), e(y.a, {
                        attrs: {
                            rules: [t.required("subject")],
                            label: "subject"
                        },
                        model: {
                            value: t.formData.subject,
                            callback: function(e) {
                                t.$set(t.formData, "subject", e)
                            },
                            expression: "formData.subject"
                        }
                    })], 1)], 1)], 1)
                }), [], !1, null, null, null);
            e.default = component.exports
        },
        579: function(t, e, r) {
            "use strict";
            r.r(e);
            r(11), r(62), r(63), r(49), r(45), r(25), r(5), r(24), r(39), r(40), r(42);
            var n = r(30);
            r(101), r(29);

            function o(t, e) {
                var r = "undefined" != typeof Symbol && t[Symbol.iterator] || t["@@iterator"];
                if (!r) {
                    if (Array.isArray(t) || (r = function(t, e) {
                            if (!t) return;
                            if ("string" == typeof t) return l(t, e);
                            var r = Object.prototype.toString.call(t).slice(8, -1);
                            "Object" === r && t.constructor && (r = t.constructor.name);
                            if ("Map" === r || "Set" === r) return Array.from(t);
                            if ("Arguments" === r || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(r)) return l(t, e)
                        }(t)) || e && t && "number" == typeof t.length) {
                        r && (t = r);
                        var i = 0,
                            n = function() {};
                        return {
                            s: n,
                            n: function() {
                                return i >= t.length ? {
                                    done: !0
                                } : {
                                    done: !1,
                                    value: t[i++]
                                }
                            },
                            e: function(t) {
                                throw t
                            },
                            f: n
                        }
                    }
                    throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")
                }
                var o, c = !0,
                    m = !1;
                return {
                    s: function() {
                        r = r.call(t)
                    },
                    n: function() {
                        var t = r.next();
                        return c = t.done, t
                    },
                    e: function(t) {
                        m = !0, o = t
                    },
                    f: function() {
                        try {
                            c || null == r.return || r.return()
                        } finally {
                            if (m) throw o
                        }
                    }
                }
            }

            function l(t, e) {
                (null == e || e > t.length) && (e = t.length);
                for (var i = 0, r = new Array(e); i < e; i++) r[i] = t[i];
                return r
            }
            var c = {
                    head: {
                        title: "Integration Edit"
                    },
                    components: {
                        IntegrationForm: r(523).default
                    },
                    methods: {
                        edit: function(data) {
                            var t = this,
                                e = this.$route.params.id;
                            return this.$axios.$patch("/admin/forms/".concat(e, "/integrations/").concat(this.$route.query.id), data).then((function(form) {
                                t.$router.push("/admin/forms/".concat(e, "/integrations"))
                            }))
                        }
                    },
                    asyncData: function(t) {
                        return Object(n.a)(regeneratorRuntime.mark((function e() {
                            var r, n, l, form, c, m, f, d;
                            return regeneratorRuntime.wrap((function(e) {
                                for (;;) switch (e.prev = e.next) {
                                    case 0:
                                        return r = t.$axios, n = t.params, l = t.route, e.next = 3, r.$get("/admin/forms/".concat(n.id));
                                    case 3:
                                        form = e.sent, c = {}, m = o(form.integrations), e.prev = 6, m.s();
                                    case 8:
                                        if ((f = m.n()).done) {
                                            e.next = 15;
                                            break
                                        }
                                        if ((d = f.value)._id.$oid !== l.query.id) {
                                            e.next = 13;
                                            break
                                        }
                                        return c = d, e.abrupt("break", 15);
                                    case 13:
                                        e.next = 8;
                                        break;
                                    case 15:
                                        e.next = 20;
                                        break;
                                    case 17:
                                        e.prev = 17, e.t0 = e.catch(6), m.e(e.t0);
                                    case 20:
                                        return e.prev = 20, m.f(), e.finish(20);
                                    case 23:
                                        return e.abrupt("return", {
                                            form: form,
                                            integration: c
                                        });
                                    case 24:
                                    case "end":
                                        return e.stop()
                                }
                            }), e, null, [
                                [6, 17, 20, 23]
                            ])
                        })))()
                    }
                },
                m = r(71),
                component = Object(m.a)(c, (function() {
                    var t = this;
                    return (0, t._self._c)("IntegrationForm", {
                        attrs: {
                            submitText: "edit",
                            submitForm: t.edit,
                            defaultData: t.integration
                        }
                    })
                }), [], !1, null, null, null);
            e.default = component.exports
        }
    }
]);