(window.webpackJsonp = window.webpackJsonp || []).push([
    [18], {
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
                l = e(71),
                component = Object(l.a)(o, (function() {
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
                l = {
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
                c = e(71),
                component = Object(c.a)(l, (function() {
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
        572: function(t, r, e) {
            "use strict";
            e.r(r);
            var n = e(83),
                o = e(532),
                l = e(527),
                c = (e(11), e(10), e(15), e(16), e(8), e(5), e(9), e(2)),
                f = e(503),
                m = e(504);

            function d(t, r) {
                var e = Object.keys(t);
                if (Object.getOwnPropertySymbols) {
                    var n = Object.getOwnPropertySymbols(t);
                    r && (n = n.filter((function(r) {
                        return Object.getOwnPropertyDescriptor(t, r).enumerable
                    }))), e.push.apply(e, n)
                }
                return e
            }
            var h = {
                    head: {
                        title: "Create Form"
                    },
                    components: {
                        SimpleForm: f.default
                    },
                    data: function() {
                        return function(t) {
                            for (var r = 1; r < arguments.length; r++) {
                                var e = null != arguments[r] ? arguments[r] : {};
                                r % 2 ? d(Object(e), !0).forEach((function(r) {
                                    Object(c.a)(t, r, e[r])
                                })) : Object.getOwnPropertyDescriptors ? Object.defineProperties(t, Object.getOwnPropertyDescriptors(e)) : d(Object(e)).forEach((function(r) {
                                    Object.defineProperty(t, r, Object.getOwnPropertyDescriptor(e, r))
                                }))
                            }
                            return t
                        }({
                            formData: {
                                published: !1,
                                title: ""
                            }
                        }, m.a)
                    },
                    methods: {
                        create: function(data) {
                            var t = this;
                            return this.$axios.$post("/admin/forms", data).then((function(form) {
                                t.$router.push("/admin/forms/".concat(form._id))
                            }))
                        }
                    }
                },
                v = h,
                O = e(71),
                component = Object(O.a)(v, (function() {
                    var t = this,
                        r = t._self._c;
                    return r(n.a, {
                        staticClass: "mx-auto",
                        attrs: {
                            width: "500"
                        }
                    }, [r("h1", [t._v("Create form")]), t._v(" "), r("SimpleForm", {
                        attrs: {
                            submitText: "create",
                            submitForm: t.create,
                            formData: t.formData
                        }
                    }, [r(o.a, {
                        attrs: {
                            label: "published"
                        },
                        model: {
                            value: t.formData.published,
                            callback: function(r) {
                                t.$set(t.formData, "published", r)
                            },
                            expression: "formData.published"
                        }
                    }), t._v(" "), r(l.a, {
                        attrs: {
                            rules: [t.required("title")],
                            label: "title"
                        },
                        model: {
                            value: t.formData.title,
                            callback: function(r) {
                                t.$set(t.formData, "title", r)
                            },
                            expression: "formData.title"
                        }
                    })], 1)], 1)
                }), [], !1, null, null, null);
            r.default = component.exports
        }
    }
]);