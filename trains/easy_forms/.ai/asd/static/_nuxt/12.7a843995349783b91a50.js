(window.webpackJsonp = window.webpackJsonp || []).push([
    [12, 9], {
        502: function(t, r, e) {
            "use strict";
            e.r(r);
            var n = e(514),
                o = {
                    methods: {
                        errorInfo: function() {
                            return this.error.response ? this.error.response.data.message : this.error
                        }
                    },
                    props: ["error"]
                },
                c = e(71),
                component = Object(c.a)(o, (function() {
                    var t = this,
                        r = t._self._c;
                    return t.error ? r(n.a, {
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
            r.default = component.exports
        },
        503: function(t, r, e) {
            "use strict";
            e.r(r);
            var n = e(224),
                o = e(531),
                c = {
                    props: ["submitForm", "submitText", "formData"],
                    components: {
                        DisplayError: e(502).default
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
                            this.error = null, this.submitForm(this.formData).catch((function(r) {
                                return t.error = r
                            }))
                        }
                    }
                },
                l = e(71),
                component = Object(l.a)(c, (function() {
                    var t = this,
                        r = t._self._c;
                    return r("div", [r(o.a, {
                        staticClass: "mt-10",
                        model: {
                            value: t.valid,
                            callback: function(r) {
                                t.valid = r
                            },
                            expression: "valid"
                        }
                    }, [t._t("default"), t._v(" "), r(n.a, {
                        staticClass: "mt-2",
                        attrs: {
                            disabled: !t.valid,
                            type: "submit",
                            block: ""
                        },
                        on: {
                            click: function(r) {
                                return r.preventDefault(), t.submit.apply(null, arguments)
                            }
                        }
                    }, [t._v(t._s(t.submitText))])], 2), t._v(" "), r("DisplayError", {
                        attrs: {
                            error: t.error
                        }
                    })], 1)
                }), [], !1, null, null, null);
            r.default = component.exports
        },
        504: function(t, r, e) {
            "use strict";
            e(29), e(24);
            r.a = {
                required: function(t) {
                    return function(r) {
                        return r && r.length > 0 || "Field ".concat(t, " is required")
                    }
                },
                email: function(t) {
                    var r = /^[A-Z0-9+_.-]+@[A-Z0-9.-]+$/i;
                    return function(e) {
                        return e && r.test(e) || "Field ".concat(t, " must be a valid email")
                    }
                },
                url: function(t) {
                    var r = /^https?:\/\/[a-z0-9+_.-]+\//;
                    return function(e) {
                        return e && r.test(e) || "Field ".concat(t, " must be a valid url")
                    }
                },
                maxlen: function(t, r) {
                    return function(e) {
                        return e && e.length < r || "Field ".concat(t, " has a ").concat(r, " character limit")
                    }
                },
                alphaNum: function(t) {
                    var r = /^[[A-Z0-9-_]+$/i;
                    return function(e) {
                        return e && r.test(e) || "Field ".concat(t, " must be a alpha or num only")
                    }
                }
            }
        },
        522: function(t, r, e) {
            "use strict";
            e.r(r);
            var n = e(224),
                o = e(498),
                c = e(501),
                l = e(218),
                f = e(520),
                m = e(568),
                d = e(83),
                v = e(527),
                h = (e(25), e(11), e(10), e(15), e(16), e(8), e(5), e(9), e(2)),
                y = (e(151), e(503)),
                D = e(504);

            function _(t, r) {
                var e = Object.keys(t);
                if (Object.getOwnPropertySymbols) {
                    var n = Object.getOwnPropertySymbols(t);
                    r && (n = n.filter((function(r) {
                        return Object.getOwnPropertyDescriptor(t, r).enumerable
                    }))), e.push.apply(e, n)
                }
                return e
            }
            var O = {
                    name: "InputForm",
                    components: {
                        SimpleForm: y.default
                    },
                    data: function() {
                        var t, r, e;
                        return function(t) {
                            for (var r = 1; r < arguments.length; r++) {
                                var e = null != arguments[r] ? arguments[r] : {};
                                r % 2 ? _(Object(e), !0).forEach((function(r) {
                                    Object(h.a)(t, r, e[r])
                                })) : Object.getOwnPropertyDescriptors ? Object.defineProperties(t, Object.getOwnPropertyDescriptors(e)) : _(Object(e)).forEach((function(r) {
                                    Object.defineProperty(t, r, Object.getOwnPropertyDescriptor(e, r))
                                }))
                            }
                            return t
                        }({
                            formData: {
                                type: (null === (t = this.defaultData) || void 0 === t ? void 0 : t.type) || "",
                                name: (null === (r = this.defaultData) || void 0 === r ? void 0 : r.name) || "",
                                settings: (null === (e = this.defaultData) || void 0 === e ? void 0 : e.settings) || {}
                            }
                        }, D.a)
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
                j = e(71),
                component = Object(j.a)(x, (function() {
                    var t = this,
                        r = t._self._c;
                    return r(d.a, {
                        staticClass: "mx-auto",
                        attrs: {
                            width: "500"
                        }
                    }, [r("h1", [t._v("Input form")]), t._v(" "), r("SimpleForm", {
                        attrs: {
                            submitText: t.submitText,
                            submitForm: t.submitForm,
                            formData: t.formData
                        }
                    }, [r(m.a, {
                        attrs: {
                            items: t.types,
                            rules: [t.required("name")],
                            label: "type",
                            dense: ""
                        },
                        model: {
                            value: t.formData.type,
                            callback: function(r) {
                                t.$set(t.formData, "type", r)
                            },
                            expression: "formData.type"
                        }
                    }), t._v(" "), r(v.a, {
                        attrs: {
                            rules: [t.required("name"), t.alphaNum("name")],
                            label: "name"
                        },
                        model: {
                            value: t.formData.name,
                            callback: function(r) {
                                t.$set(t.formData, "name", r)
                            },
                            expression: "formData.name"
                        }
                    }), t._v(" "), "radio" == t.formData.type ? r(c.a, [t._l(this.options(), (function(option, i) {
                        return r(f.a, {
                            key: "option_".concat(i)
                        }, [r(o.a, {
                            attrs: {
                                cols: "10"
                            }
                        }, [r(v.a, {
                            attrs: {
                                label: "Option value"
                            },
                            model: {
                                value: t.formData.settings.options[i],
                                callback: function(r) {
                                    t.$set(t.formData.settings.options, i, r)
                                },
                                expression: "formData.settings.options[i]"
                            }
                        })], 1), t._v(" "), r(o.a, {
                            attrs: {
                                cols: "2"
                            }
                        }, [r(n.a, {
                            attrs: {
                                small: ""
                            },
                            on: {
                                click: function(r) {
                                    return r.preventDefault(), t.removeOption(i)
                                }
                            }
                        }, [r(l.a, {
                            attrs: {
                                color: "primary"
                            }
                        }, [t._v("mdi-minus")])], 1)], 1)], 1)
                    })), t._v(" "), this.options().length < 5 ? r(f.a, [r(o.a, {
                        staticClass: "text-right",
                        attrs: {
                            cols: "12"
                        }
                    }, [r(n.a, {
                        on: {
                            click: function(r) {
                                return r.preventDefault(), t.addOption()
                            }
                        }
                    }, [r(l.a, {
                        attrs: {
                            color: "primary"
                        }
                    }, [t._v("mdi-plus")])], 1)], 1)], 1) : t._e()], 2) : t._e()], 1)], 1)
                }), [], !1, null, null, null);
            r.default = component.exports
        },
        577: function(t, r, e) {
            "use strict";
            e.r(r);
            e(11), e(62), e(63), e(49), e(45), e(25), e(5), e(24), e(39), e(40), e(42);
            var n = e(30);
            e(101), e(29);

            function o(t, r) {
                var e = "undefined" != typeof Symbol && t[Symbol.iterator] || t["@@iterator"];
                if (!e) {
                    if (Array.isArray(t) || (e = function(t, r) {
                            if (!t) return;
                            if ("string" == typeof t) return c(t, r);
                            var e = Object.prototype.toString.call(t).slice(8, -1);
                            "Object" === e && t.constructor && (e = t.constructor.name);
                            if ("Map" === e || "Set" === e) return Array.from(t);
                            if ("Arguments" === e || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(e)) return c(t, r)
                        }(t)) || r && t && "number" == typeof t.length) {
                        e && (t = e);
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
                var o, l = !0,
                    f = !1;
                return {
                    s: function() {
                        e = e.call(t)
                    },
                    n: function() {
                        var t = e.next();
                        return l = t.done, t
                    },
                    e: function(t) {
                        f = !0, o = t
                    },
                    f: function() {
                        try {
                            l || null == e.return || e.return()
                        } finally {
                            if (f) throw o
                        }
                    }
                }
            }

            function c(t, r) {
                (null == r || r > t.length) && (r = t.length);
                for (var i = 0, e = new Array(r); i < r; i++) e[i] = t[i];
                return e
            }
            var l = {
                    head: {
                        title: "Input Add"
                    },
                    components: {
                        InputForm: e(522).default
                    },
                    methods: {
                        edit: function(data) {
                            var t = this,
                                r = this.$route.params.id;
                            return this.$axios.$patch("/admin/forms/".concat(r, "/inputs/").concat(this.$route.query.id), data).then((function(form) {
                                t.$router.push("/admin/forms/".concat(r))
                            }))
                        }
                    },
                    asyncData: function(t) {
                        return Object(n.a)(regeneratorRuntime.mark((function r() {
                            var e, n, c, form, input, l, f, m;
                            return regeneratorRuntime.wrap((function(r) {
                                for (;;) switch (r.prev = r.next) {
                                    case 0:
                                        return e = t.$axios, n = t.params, c = t.route, r.next = 3, e.$get("/admin/forms/".concat(n.id));
                                    case 3:
                                        form = r.sent, input = {}, l = o(form.inputs), r.prev = 6, l.s();
                                    case 8:
                                        if ((f = l.n()).done) {
                                            r.next = 15;
                                            break
                                        }
                                        if ((m = f.value)._id.$oid !== c.query.id) {
                                            r.next = 13;
                                            break
                                        }
                                        return input = m, r.abrupt("break", 15);
                                    case 13:
                                        r.next = 8;
                                        break;
                                    case 15:
                                        r.next = 20;
                                        break;
                                    case 17:
                                        r.prev = 17, r.t0 = r.catch(6), l.e(r.t0);
                                    case 20:
                                        return r.prev = 20, l.f(), r.finish(20);
                                    case 23:
                                        return r.abrupt("return", {
                                            form: form,
                                            input: input
                                        });
                                    case 24:
                                    case "end":
                                        return r.stop()
                                }
                            }), r, null, [
                                [6, 17, 20, 23]
                            ])
                        })))()
                    }
                },
                f = e(71),
                component = Object(f.a)(l, (function() {
                    var t = this;
                    return (0, t._self._c)("InputForm", {
                        attrs: {
                            submitText: "edit",
                            submitForm: t.edit,
                            defaultData: t.input
                        }
                    })
                }), [], !1, null, null, null);
            r.default = component.exports
        }
    }
]);