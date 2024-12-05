(window.webpackJsonp = window.webpackJsonp || []).push([
    [14, 10], {
        502: function(t, e, r) {
            "use strict";
            r.r(e);
            var o = r(514),
                n = {
                    methods: {
                        errorInfo: function() {
                            return this.error.response ? this.error.response.data.message : this.error
                        }
                    },
                    props: ["error"]
                },
                l = r(71),
                component = Object(l.a)(n, (function() {
                    var t = this,
                        e = t._self._c;
                    return t.error ? e(o.a, {
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
            var o = r(224),
                n = r(531),
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
                    return e("div", [e(n.a, {
                        staticClass: "mt-10",
                        model: {
                            value: t.valid,
                            callback: function(e) {
                                t.valid = e
                            },
                            expression: "valid"
                        }
                    }, [t._t("default"), t._v(" "), e(o.a, {
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
            var o = r(224),
                n = r(498),
                l = r(501),
                c = r(488),
                m = r(218),
                f = r(520),
                d = r(568),
                v = r(83),
                h = r(532),
                _ = r(527),
                D = r(556),
                y = (r(25), r(11), r(10), r(15), r(16), r(8), r(5), r(9), r(2)),
                x = (r(151), r(503)),
                O = r(504);

            function j(t, e) {
                var r = Object.keys(t);
                if (Object.getOwnPropertySymbols) {
                    var o = Object.getOwnPropertySymbols(t);
                    e && (o = o.filter((function(e) {
                        return Object.getOwnPropertyDescriptor(t, e).enumerable
                    }))), r.push.apply(r, o)
                }
                return r
            }

            function k(t) {
                for (var e = 1; e < arguments.length; e++) {
                    var r = null != arguments[e] ? arguments[e] : {};
                    e % 2 ? j(Object(r), !0).forEach((function(e) {
                        Object(y.a)(t, e, r[e])
                    })) : Object.getOwnPropertyDescriptors ? Object.defineProperties(t, Object.getOwnPropertyDescriptors(r)) : j(Object(r)).forEach((function(e) {
                        Object.defineProperty(t, e, Object.getOwnPropertyDescriptor(r, e))
                    }))
                }
                return t
            }
            var F = {
                    name: "IntegrationForm",
                    components: {
                        SimpleForm: x.default
                    },
                    data: function() {
                        return k({
                            formData: k({
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
                $ = r(71),
                component = Object($.a)(F, (function() {
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
                    }), t._v(" "), e(_.a, {
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
                    }), t._v(" "), "api" === t.formData.type ? e("div", [e(_.a, {
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
                        }, [e(n.a, {
                            attrs: {
                                cols: "5"
                            }
                        }, [e(_.a, {
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
                        })], 1), t._v(" "), e(n.a, {
                            attrs: {
                                cols: "5"
                            }
                        }, [e(_.a, {
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
                        })], 1), t._v(" "), e(n.a, {
                            attrs: {
                                cols: "2"
                            }
                        }, [e(o.a, {
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
                    })), t._v(" "), t.formData.headers.length < 10 ? e(f.a, [e(n.a, {
                        staticClass: "text-right",
                        attrs: {
                            cols: "12"
                        }
                    }, [e(o.a, {
                        on: {
                            click: function(e) {
                                return e.preventDefault(), t.addHeader()
                            }
                        }
                    }, [e(m.a, {
                        attrs: {
                            color: "primary"
                        }
                    }, [t._v("mdi-plus")])], 1)], 1)], 1) : t._e()], 2), t._v(" "), "POST" === t.formData.method ? e(l.a, [e(f.a, [e(n.a, {
                        attrs: {
                            cols: "12"
                        }
                    }, [e("i", [t._v("Add a %FORM_RESULT% template that will pass the form results")])]), t._v(" "), e(n.a, {
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
                    })], 1)], 1)], 1) : t._e()], 1) : e("div", [e(_.a, {
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
                    }), t._v(" "), e(_.a, {
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
                    }), t._v(" "), e(_.a, {
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
        578: function(t, e, r) {
            "use strict";
            r.r(e);
            var o = {
                    head: {
                        title: "Integration Add"
                    },
                    components: {
                        IntegrationForm: r(523).default
                    },
                    methods: {
                        create: function(data) {
                            var t = this,
                                e = this.$route.params.id;
                            return this.$axios.$post("/admin/forms/".concat(e, "/integrations"), data).then((function(form) {
                                t.$router.push("/admin/forms/".concat(e, "/integrations"))
                            }))
                        }
                    }
                },
                n = r(71),
                component = Object(n.a)(o, (function() {
                    return (0, this._self._c)("IntegrationForm", {
                        attrs: {
                            submitText: "add",
                            submitForm: this.create
                        }
                    })
                }), [], !1, null, null, null);
            e.default = component.exports
        }
    }
]);