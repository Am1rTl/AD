(window.webpackJsonp = window.webpackJsonp || []).push([
    [20], {
        485: function(t, e, n) {
            "use strict";
            n.d(e, "a", (function() {
                return c
            })), n.d(e, "b", (function() {
                return f
            })), n.d(e, "c", (function() {
                return d
            }));
            var r = n(486),
                o = n(0),
                c = Object(o.f)("v-card__actions"),
                l = Object(o.f)("v-card__subtitle"),
                f = Object(o.f)("v-card__text"),
                d = Object(o.f)("v-card__title");
            r.a
        },
        520: function(t, e, n) {
            "use strict";
            var r = n(2),
                o = (n(11), n(29), n(10), n(41), n(308), n(15), n(16), n(8), n(5), n(24), n(68), n(40), n(61), n(309), n(310), n(311), n(312), n(313), n(314), n(315), n(316), n(317), n(318), n(319), n(320), n(321), n(9), n(42), n(230), n(1)),
                c = n(77),
                l = n(0);

            function f(t, e) {
                var n = Object.keys(t);
                if (Object.getOwnPropertySymbols) {
                    var r = Object.getOwnPropertySymbols(t);
                    e && (r = r.filter((function(e) {
                        return Object.getOwnPropertyDescriptor(t, e).enumerable
                    }))), n.push.apply(n, r)
                }
                return n
            }

            function d(t) {
                for (var e = 1; e < arguments.length; e++) {
                    var n = null != arguments[e] ? arguments[e] : {};
                    e % 2 ? f(Object(n), !0).forEach((function(e) {
                        Object(r.a)(t, e, n[e])
                    })) : Object.getOwnPropertyDescriptors ? Object.defineProperties(t, Object.getOwnPropertyDescriptors(n)) : f(Object(n)).forEach((function(e) {
                        Object.defineProperty(t, e, Object.getOwnPropertyDescriptor(n, e))
                    }))
                }
                return t
            }
            var v = ["sm", "md", "lg", "xl"],
                m = ["start", "end", "center"];

            function j(t, e) {
                return v.reduce((function(n, r) {
                    return n[t + Object(l.u)(r)] = e(), n
                }), {})
            }
            var y = function(t) {
                    return [].concat(m, ["baseline", "stretch"]).includes(t)
                },
                O = j("align", (function() {
                    return {
                        type: String,
                        default: null,
                        validator: y
                    }
                })),
                h = function(t) {
                    return [].concat(m, ["space-between", "space-around"]).includes(t)
                },
                _ = j("justify", (function() {
                    return {
                        type: String,
                        default: null,
                        validator: h
                    }
                })),
                w = function(t) {
                    return [].concat(m, ["space-between", "space-around", "stretch"]).includes(t)
                },
                x = j("alignContent", (function() {
                    return {
                        type: String,
                        default: null,
                        validator: w
                    }
                })),
                k = {
                    align: Object.keys(O),
                    justify: Object.keys(_),
                    alignContent: Object.keys(x)
                },
                S = {
                    align: "align",
                    justify: "justify",
                    alignContent: "align-content"
                };

            function C(t, e, n) {
                var r = S[t];
                if (null != n) {
                    if (e) {
                        var o = e.replace(t, "");
                        r += "-".concat(o)
                    }
                    return (r += "-".concat(n)).toLowerCase()
                }
            }
            var P = new Map;
            e.a = o.a.extend({
                name: "v-row",
                functional: !0,
                props: d(d(d({
                    tag: {
                        type: String,
                        default: "div"
                    },
                    dense: Boolean,
                    noGutters: Boolean,
                    align: {
                        type: String,
                        default: null,
                        validator: y
                    }
                }, O), {}, {
                    justify: {
                        type: String,
                        default: null,
                        validator: h
                    }
                }, _), {}, {
                    alignContent: {
                        type: String,
                        default: null,
                        validator: w
                    }
                }, x),
                render: function(t, e) {
                    var n = e.props,
                        data = e.data,
                        o = e.children,
                        l = "";
                    for (var f in n) l += String(n[f]);
                    var d = P.get(l);
                    if (!d) {
                        var v;
                        for (v in d = [], k) k[v].forEach((function(t) {
                            var e = n[t],
                                r = C(v, t, e);
                            r && d.push(r)
                        }));
                        d.push(Object(r.a)(Object(r.a)(Object(r.a)({
                            "no-gutters": n.noGutters,
                            "row--dense": n.dense
                        }, "align-".concat(n.align), n.align), "justify-".concat(n.justify), n.justify), "align-content-".concat(n.alignContent), n.alignContent)), P.set(l, d)
                    }
                    return t(n.tag, Object(c.a)(data, {
                        staticClass: "row",
                        class: d
                    }), o)
                }
            })
        },
        573: function(t, e, n) {
            "use strict";
            n.r(e);
            var r = n(224),
                o = n(486),
                c = n(485),
                l = n(498),
                f = n(501),
                d = n(218),
                v = n(520),
                m = n(83),
                j = (n(8), n(30)),
                y = (n(101), {
                    name: "FormIndex",
                    head: {
                        title: "Home"
                    },
                    data: function() {
                        return {
                            forms: {}
                        }
                    },
                    methods: {
                        truncFormTitle: function(form) {
                            return form.title.length <= 40 ? form.title : form.title.substr(0, 40) + "..."
                        },
                        formColor: function(form) {
                            var t = this.$vuetify.theme.themes.light;
                            return form.published ? t.primary : t.secondary
                        },
                        removeForm: function(t, e) {
                            var n = this;
                            return Object(j.a)(regeneratorRuntime.mark((function r() {
                                return regeneratorRuntime.wrap((function(r) {
                                    for (;;) switch (r.prev = r.next) {
                                        case 0:
                                            return r.next = 2, n.$axios.$delete("/admin/forms/".concat(t));
                                        case 2:
                                            n.$delete(n.forms, e);
                                        case 3:
                                        case "end":
                                            return r.stop()
                                    }
                                }), r)
                            })))()
                        }
                    },
                    fetch: function() {
                        var t = this;
                        return Object(j.a)(regeneratorRuntime.mark((function e() {
                            return regeneratorRuntime.wrap((function(e) {
                                for (;;) switch (e.prev = e.next) {
                                    case 0:
                                        return e.next = 2, t.$axios.$get("/admin/forms");
                                    case 2:
                                        t.forms = e.sent;
                                    case 3:
                                    case "end":
                                        return e.stop()
                                }
                            }), e)
                        })))()
                    },
                    fetchOnServer: !1,
                    fetchKey: "forms"
                }),
                O = n(71),
                component = Object(O.a)(y, (function() {
                    var t = this,
                        e = t._self._c;
                    return e(v.a, {
                        attrs: {
                            justify: "center",
                            align: "center"
                        }
                    }, [e(f.a, [Object.keys(t.forms).length ? t._e() : e(m.a, [e("p", [t._v("You don't have forms yet, create them!")])]), t._v(" "), e(v.a, t._l(t.forms, (function(form, i) {
                        return e(l.a, {
                            key: form.id,
                            attrs: {
                                cols: "6",
                                md: "3"
                            }
                        }, [e(m.a, {
                            attrs: {
                                height: "150"
                            }
                        }, [e(o.a, {
                            attrs: {
                                color: t.formColor(form),
                                to: "/admin/forms/".concat(form._id),
                                nuxt: ""
                            }
                        }, [e(c.c, [t._v(t._s(t.truncFormTitle(form)))]), t._v(" "), e(c.b, [e(v.a, [e("p")])], 1), t._v(" "), e(c.a, [e(r.a, {
                            attrs: {
                                icon: ""
                            },
                            on: {
                                click: function(e) {
                                    return e.preventDefault(), t.removeForm(form._id, i)
                                }
                            }
                        }, [e(d.a, {
                            attrs: {
                                color: "error"
                            }
                        }, [t._v("mdi-delete")])], 1), t._v(" "), e(r.a, {
                            attrs: {
                                to: "/forms/".concat(form._id),
                                icon: "",
                                nuxt: ""
                            }
                        }, [e(d.a, [t._v("mdi-send")])], 1)], 1)], 1)], 1)], 1)
                    })), 1)], 1)], 1)
                }), [], !1, null, null, null);
            e.default = component.exports
        }
    }
]);