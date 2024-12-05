(window.webpackJsonp = window.webpackJsonp || []).push([
    [13], {
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
        574: function(t, r, e) {
            "use strict";
            e.r(r);
            var n = e(224),
                o = e(498),
                c = e(218),
                l = e(221),
                f = e(143),
                m = e(222),
                d = e(232),
                v = e(520),
                h = e(83),
                _ = e(532),
                O = e(527),
                y = (e(29), e(25), e(11), e(10), e(15), e(16), e(8), e(5), e(9), e(30)),
                j = e(2),
                w = (e(101), e(503)),
                x = e(504);

            function $(t, r) {
                var e = Object.keys(t);
                if (Object.getOwnPropertySymbols) {
                    var n = Object.getOwnPropertySymbols(t);
                    r && (n = n.filter((function(r) {
                        return Object.getOwnPropertyDescriptor(t, r).enumerable
                    }))), e.push.apply(e, n)
                }
                return e
            }
            var D = {
                    head: {
                        title: "Form"
                    },
                    components: {
                        SimpleForm: w.default
                    },
                    data: function() {
                        return function(t) {
                            for (var r = 1; r < arguments.length; r++) {
                                var e = null != arguments[r] ? arguments[r] : {};
                                r % 2 ? $(Object(e), !0).forEach((function(r) {
                                    Object(j.a)(t, r, e[r])
                                })) : Object.getOwnPropertyDescriptors ? Object.defineProperties(t, Object.getOwnPropertyDescriptors(e)) : $(Object(e)).forEach((function(r) {
                                    Object.defineProperty(t, r, Object.getOwnPropertyDescriptor(e, r))
                                }))
                            }
                            return t
                        }({
                            inputs: []
                        }, x.a)
                    },
                    methods: {
                        update: function(data) {
                            var t = this;
                            return this.$axios.$patch("/admin/forms/".concat(this.form._id), data).then((function(form) {
                                return t.$router.go()
                            }))
                        },
                        removeInput: function(input, t) {
                            var r = this;
                            this.$axios.$delete("/admin/forms/".concat(this.form._id, "/inputs/").concat(input._id.$oid)).then((function(form) {
                                r.$delete(r.form.inputs, t)
                            }))
                        }
                    },
                    asyncData: function(t) {
                        return Object(y.a)(regeneratorRuntime.mark((function r() {
                            var e, n, form;
                            return regeneratorRuntime.wrap((function(r) {
                                for (;;) switch (r.prev = r.next) {
                                    case 0:
                                        return e = t.$axios, n = t.params, r.next = 3, e.$get("/admin/forms/".concat(n.id));
                                    case 3:
                                        return form = r.sent, r.abrupt("return", {
                                            form: form,
                                            title: form.title
                                        });
                                    case 5:
                                    case "end":
                                        return r.stop()
                                }
                            }), r)
                        })))()
                    }
                },
                F = D,
                k = e(71),
                component = Object(k.a)(F, (function() {
                    var t = this,
                        r = t._self._c;
                    return r(h.a, [r("h1", [t._v(t._s(t.title))]), t._v(" "), r(v.a, {
                        staticClass: "mt-10"
                    }, [r(o.a, [r(h.a, {
                        attrs: {
                            width: "350"
                        }
                    }, [r("SimpleForm", {
                        attrs: {
                            submitText: "update",
                            submitForm: t.update,
                            formData: t.form
                        }
                    }, [r(_.a, {
                        attrs: {
                            label: "published"
                        },
                        model: {
                            value: t.form.published,
                            callback: function(r) {
                                t.$set(t.form, "published", r)
                            },
                            expression: "form.published"
                        }
                    }), t._v(" "), r(O.a, {
                        attrs: {
                            rules: [t.required("title")],
                            label: "title"
                        },
                        model: {
                            value: t.form.title,
                            callback: function(r) {
                                t.$set(t.form, "title", r)
                            },
                            expression: "form.title"
                        }
                    })], 1)], 1)], 1), t._v(" "), r(o.a, [r("h3", [t._v("Form fields")]), t._v(" "), r(h.a, {
                        staticClass: "mt-5",
                        attrs: {
                            width: "350"
                        }
                    }, [r(n.a, {
                        attrs: {
                            small: "",
                            to: "/admin/forms/".concat(t.form._id, "/fields/create")
                        }
                    }, [t._v(" add field ")]), t._v(" "), r(l.a, [t._l(t.form.inputs, (function(input, e) {
                        return [r(f.a, [r(d.a, [t._v("\n                  " + t._s(input.type) + "\n                ")]), t._v(" "), r(d.a, {
                            staticClass: "px-5"
                        }, [t._v("\n                  " + t._s(input.name) + "\n                ")]), t._v(" "), r(m.a, [r(n.a, {
                            attrs: {
                                icon: "",
                                to: "/admin/forms/".concat(t.form._id, "/fields/edit?id=").concat(input._id.$oid)
                            }
                        }, [r(c.a, [t._v("mdi-pencil")])], 1)], 1), t._v(" "), r(m.a, [r(n.a, {
                            attrs: {
                                icon: ""
                            },
                            on: {
                                click: function(r) {
                                    return r.preventDefault(), t.removeInput(input, e)
                                }
                            }
                        }, [r(c.a, {
                            attrs: {
                                color: "error"
                            }
                        }, [t._v("mdi-delete")])], 1)], 1)], 1)]
                    }))], 2)], 1)], 1)], 1)], 1)
                }), [], !1, null, null, null);
            r.default = component.exports
        }
    }
]);