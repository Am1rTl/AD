(window.webpackJsonp = window.webpackJsonp || []).push([
    [11, 9], {
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
        522: function(t, e, r) {
            "use strict";
            r.r(e);
            var n = r(224),
                o = r(498),
                l = r(501),
                c = r(218),
                m = r(520),
                f = r(568),
                d = r(83),
                v = r(527),
                h = (r(25), r(11), r(10), r(15), r(16), r(8), r(5), r(9), r(2)),
                D = (r(151), r(503)),
                _ = r(504);

            function y(t, e) {
                var r = Object.keys(t);
                if (Object.getOwnPropertySymbols) {
                    var n = Object.getOwnPropertySymbols(t);
                    e && (n = n.filter((function(e) {
                        return Object.getOwnPropertyDescriptor(t, e).enumerable
                    }))), r.push.apply(r, n)
                }
                return r
            }
            var O = {
                    name: "InputForm",
                    components: {
                        SimpleForm: D.default
                    },
                    data: function() {
                        var t, e, r;
                        return function(t) {
                            for (var e = 1; e < arguments.length; e++) {
                                var r = null != arguments[e] ? arguments[e] : {};
                                e % 2 ? y(Object(r), !0).forEach((function(e) {
                                    Object(h.a)(t, e, r[e])
                                })) : Object.getOwnPropertyDescriptors ? Object.defineProperties(t, Object.getOwnPropertyDescriptors(r)) : y(Object(r)).forEach((function(e) {
                                    Object.defineProperty(t, e, Object.getOwnPropertyDescriptor(r, e))
                                }))
                            }
                            return t
                        }({
                            formData: {
                                type: (null === (t = this.defaultData) || void 0 === t ? void 0 : t.type) || "",
                                name: (null === (e = this.defaultData) || void 0 === e ? void 0 : e.name) || "",
                                settings: (null === (r = this.defaultData) || void 0 === r ? void 0 : r.settings) || {}
                            }
                        }, _.a)
                    },
                    methods: {
                        options: function() {
                            return this.formData.settings.options || (this.$set(this.formData.settings, "options", []), this.formData.settings.options.push("value_1")), this.formData.settings.options
                        },
                        addOption: function() {
                            var t = this.formData.settings.options;
                            t.push("value_".concat(t.length + 1))
                        },
                        removeOption: function(t) {
                            this.formData.settings.options.splice(t, 1)
                        }
                    },
                    props: {
                        types: {
                            default: function() {
                                return ["text", "radio", "checkbox", "textarea"]
                            }
                        },
                        submitForm: {},
                        submitText: {},
                        defaultData: {}
                    }
                },
                x = O,
                j = r(71),
                component = Object(j.a)(x, (function() {
                    var t = this,
                        e = t._self._c;
                    return e(d.a, {
                        staticClass: "mx-auto",
                        attrs: {
                            width: "500"
                        }
                    }, [e("h1", [t._v("Input form")]), t._v(" "), e("SimpleForm", {
                        attrs: {
                            submitText: t.submitText,
                            submitForm: t.submitForm,
                            formData: t.formData
                        }
                    }, [e(f.a, {
                        attrs: {
                            items: t.types,
                            rules: [t.required("name")],
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
                    }), t._v(" "), e(v.a, {
                        attrs: {
                            rules: [t.required("name"), t.alphaNum("name")],
                            label: "name"
                        },
                        model: {
                            value: t.formData.name,
                            callback: function(e) {
                                t.$set(t.formData, "name", e)
                            },
                            expression: "formData.name"
                        }
                    }), t._v(" "), "radio" == t.formData.type ? e(l.a, [t._l(this.options(), (function(option, i) {
                        return e(m.a, {
                            key: "option_".concat(i)
                        }, [e(o.a, {
                            attrs: {
                                cols: "10"
                            }
                        }, [e(v.a, {
                            attrs: {
                                label: "Option value"
                            },
                            model: {
                                value: t.formData.settings.options[i],
                                callback: function(e) {
                                    t.$set(t.formData.settings.options, i, e)
                                },
                                expression: "formData.settings.options[i]"
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
                                    return e.preventDefault(), t.removeOption(i)
                                }
                            }
                        }, [e(c.a, {
                            attrs: {
                                color: "primary"
                            }
                        }, [t._v("mdi-minus")])], 1)], 1)], 1)
                    })), t._v(" "), this.options().length < 5 ? e(m.a, [e(o.a, {
                        staticClass: "text-right",
                        attrs: {
                            cols: "12"
                        }
                    }, [e(n.a, {
                        on: {
                            click: function(e) {
                                return e.preventDefault(), t.addOption()
                            }
                        }
                    }, [e(c.a, {
                        attrs: {
                            color: "primary"
                        }
                    }, [t._v("mdi-plus")])], 1)], 1)], 1) : t._e()], 2) : t._e()], 1)], 1)
                }), [], !1, null, null, null);
            e.default = component.exports
        },
        576: function(t, e, r) {
            "use strict";
            r.r(e);
            var n = {
                    head: {
                        title: "Input Add"
                    },
                    components: {
                        InputForm: r(522).default
                    },
                    methods: {
                        create: function(data) {
                            var t = this,
                                e = this.$route.params.id;
                            return this.$axios.$post("/admin/forms/".concat(e, "/inputs"), data).then((function(form) {
                                t.$router.push("/admin/forms/".concat(e))
                            }))
                        }
                    }
                },
                o = r(71),
                component = Object(o.a)(n, (function() {
                    return (0, this._self._c)("InputForm", {
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