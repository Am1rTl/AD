(ns build
  (:refer-clojure :exclude [test])
  (:require [org.corfield.build :as bb]))

(def lib 'ctf/quoter)
(def main 'backend.core)

(defn list-resources [path]
  (let [jar (java.util.jar.JarFile. "target/quoter-standalone.jar")
        entries (.entries jar)]
    (print "Jar content")
    (loop [result []]
      (if (.hasMoreElements entries)
        (recur (conj result (.. entries nextElement getName)))
        result))))

(defn prep [opts]
  (bb/clean opts)
  (print "done"))

(defn ci "Run the CI pipeline." [opts]
  (-> opts
      (assoc :lib lib :main main :src-dirs ["src/" "resources/"])
      (bb/uber)))

(defn build "Build the uberjar of project" [opts]
  (-> opts
      (assoc :lib lib :main main :src-dirs ["src/" "resources/"])
      (bb/clean)
      (bb/uber)))
