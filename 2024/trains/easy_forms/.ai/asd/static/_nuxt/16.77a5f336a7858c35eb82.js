(window.webpackJsonp = window.webpackJsonp || []).push([
    [16], {
        485: function(t, n, e) {
            "use strict";
            e.d(n, "a", (function() {
                return c
            })), e.d(n, "b", (function() {
                return f
            })), e.d(n, "c", (function() {
                return d
            }));
            var r = e(486),
                o = e(0),
                c = Object(o.f)("v-card__actions"),
                l = Object(o.f)("v-card__subtitle"),
                f = Object(o.f)("v-card__text"),
                d = Object(o.f)("v-card__title");
            r.a
        },
        520: function(t, n, e) {
            "use strict";
            var r = e(2),
                o = (e(11), e(29), e(10), e(41), e(308), e(15), e(16), e(8), e(5), e(24), e(68), e(40), e(61), e(309), e(310), e(311), e(312), e(313), e(314), e(315), e(316), e(317), e(318), e(319), e(320), e(321), e(9), e(42), e(230), e(1)),
                c = e(77),
                l = e(0);

            function f(t, n) {
                var e = Object.keys(t);
                if (Object.getOwnPropertySymbols) {
                    var r = Object.getOwnPropertySymbols(t);
                    n && (r = r.filter((function(n) {
                        return Object.getOwnPropertyDescriptor(t, n).enumerable
                    }))), e.push.apply(e, r)
                }
                return e
            }

            function d(t) {
                for (var n = 1; n < arguments.length; n++) {
                    var e = null != arguments[n] ? arguments[n] : {};
                    n % 2 ? f(Object(e), !0).forEach((function(n) {
                        Object(r.a)(t, n, e[n])
                    })) : Object.getOwnPropertyDescriptors ? Object.defineProperties(t, Object.getOwnPropertyDescriptors(e)) : f(Object(e)).forEach((function(n) {
                        Object.defineProperty(t, n, Object.getOwnPropertyDescriptor(e, n))
                    }))
                }
                return t
            }
            var v = ["sm", "md", "lg", "xl"],
                m = ["start", "end", "center"];

            function j(t, n) {
                return v.reduce((function(e, r) {
                    return e[t + Object(l.u)(r)] = n(), e
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
                _ = function(t) {
                    return [].concat(m, ["space-between", "space-around"]).includes(t)
                },
                h = j("justify", (function() {
                    return {
                        type: String,
                        default: null,
                        validator: _
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
                C = {
                    align: Object.keys(O),
                    justify: Object.keys(h),
                    alignContent: Object.keys(x)
                },
                k = {
                    align: "align",
                    justify: "justify",
                    alignContent: "align-content"
                };

            function S(t, n, e) {
                var r = k[t];
                if (null != e) {
                    if (n) {
                        var o = n.replace(t, "");
                        r += "-".concat(o)
                    }
                    return (r += "-".concat(e)).toLowerCase()
                }
            }
            var $ = new Map;
            n.a = o.a.extend({
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
                        validator: _
                    }
                }, h), {}, {
                    alignContent: {
                        type: String,
                        default: null,
                        validator: w
                    }
                }, x),
                render: function(t, n) {
                    var e = n.props,
                        data = n.data,
                        o = n.children,
                        l = "";
                    for (var f in e) l += String(e[f]);
                    var d = $.get(l);
                    if (!d) {
                        var v;
                        for (v in d = [], C) C[v].forEach((function(t) {
                            var n = e[t],
                                r = S(v, t, n);
                            r && d.push(r)
                        }));
                        d.push(Object(r.a)(Object(r.a)(Object(r.a)({
                            "no-gutters": e.noGutters,
                            "row--dense": e.dense
                        }, "align-".concat(e.align), e.align), "justify-".concat(e.justify), e.justify), "align-content-".concat(e.alignContent), e.alignContent)), $.set(l, d)
                    }
                    return t(e.tag, Object(c.a)(data, {
                        staticClass: "row",
                        class: d
                    }), o)
                }
            })
        },
        575: function(t, n, e) {
            "use strict";
            e.r(n);
            var r = e(224),
                o = e(486),
                c = e(485),
                l = e(498),
                f = e(501),
                d = e(218),
                v = e(520),
                m = e(83),
                j = (e(29), e(30)),
                y = (e(101), {
                    head: {
                        title: "Form Integrations"
                    },
                    methods: {
                        integrationColor: function(t) {
                            var n = this.$vuetify.theme.themes.light;
                            return t.active ? n.primary : n.secondary
                        },
                        removeIntegration: function(t, n) {
                            var e = this;
                            return Object(j.a)(regeneratorRuntime.mark((function r() {
                                return regeneratorRuntime.wrap((function(r) {
                                    for (;;) switch (r.prev = r.next) {
                                        case 0:
                                            return r.next = 2, e.$axios.$delete("/admin/forms/".concat(t, "/integrations/").concat(n)).then((function(form) {
                                                e.$set(e.form, "integrations", form.integraions)
                                            }));
                                        case 2:
                                        case "end":
                                            return r.stop()
                                    }
                                }), r)
                            })))()
                        }
                    },
                    asyncData: function(t) {
                        return Object(j.a)(regeneratorRuntime.mark((function n() {
                            var e, r, form;
                            return regeneratorRuntime.wrap((function(n) {
                                for (;;) switch (n.prev = n.next) {
                                    case 0:
                                        return e = t.$axios, r = t.params, t.route, n.next = 3, e.$get("/admin/forms/".concat(r.id));
                                    case 3:
                                        return form = n.sent, n.abrupt("return", {
                                            form: form
                                        });
                                    case 5:
                                    case "end":
                                        return n.stop()
                                }
                            }), n)
                        })))()
                    }
                }),
                O = e(71),
                component = Object(O.a)(y, (function() {
                    var t = this,
                        n = t._self._c;
                    return n(m.a, [n("h1", [t._v("Form integrations")]), t._v(" "), n(r.a, {
                        staticClass: "my-5",
                        attrs: {
                            small: "",
                            to: "/admin/forms/".concat(t.form._id, "/integrations/create")
                        }
                    }, [t._v(" add integraion ")]), t._v(" "), n(v.a, [n(f.a, [n(v.a, t._l(t.form.integrations, (function(e, i) {
                        return n(l.a, {
                            key: e._id.$oid,
                            attrs: {
                                cols: "6",
                                md: "3"
                            }
                        }, [n(m.a, {
                            attrs: {
                                height: "150"
                            }
                        }, [n(o.a, {
                            attrs: {
                                color: t.integrationColor(e),
                                to: "/admin/forms/".concat(t.form._id, "/integrations/edit?id=").concat(e._id.$oid),
                                nuxt: ""
                            }
                        }, [n(c.c, [t._v(t._s(e.title))]), t._v(" "), n(c.b, [n(v.a, [n("p")])], 1), t._v(" "), n(c.a, [n(r.a, {
                            attrs: {
                                icon: ""
                            },
                            on: {
                                click: function(n) {
                                    return n.preventDefault(), t.removeIntegration(t.form._id, e._id.$oid, i)
                                }
                            }
                        }, [n(d.a, {
                            attrs: {
                                color: "error"
                            }
                        }, [t._v("mdi-delete")])], 1)], 1)], 1)], 1)], 1)
                    })), 1)], 1)], 1)], 1)
                }), [], !1, null, null, null);
            n.default = component.exports
        }
    }
]);